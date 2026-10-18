<?php
/*
 * ComSense agent - remote terminal.
 *
 * Off unless "Remote terminal" is ticked in Services > ComSense Agent. An
 * admin approves each session in the console with their authenticator app;
 * the server then queues an open_terminal task. The task only leaves a
 * request file: comsense-agentd starts "agent.php terminal <id>" outside the
 * check-in cycle (whose timeout(1) would wait for it), and that helper:
 *
 *   1. opens a WebSocket to the agent API (outgoing, same TLS checks and
 *      key pin as every other request, through the pfSense proxy if set),
 *   2. starts a login shell on a pseudo-terminal with script(1),
 *   3. copies keystrokes in and output out until either side ends it.
 *
 * The server ends idle and over-long sessions and records them; the helper
 * also gives up after CSFM_TERM_MAX_SECONDS on its own.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');

if (!defined('CSFM_TERM_DIR')) {
	define('CSFM_TERM_DIR', CSFM_DB_DIR . '/terminal');
}
define('CSFM_TERM_MAX_SECONDS', 3 * 3600);
define('CSFM_TERM_SID_RE', '/^[A-Za-z0-9_-]{16,64}$/');

/* Minimal WebSocket client (RFC 6455) over a PHP TLS stream. */
class CsfmWebSocket {
	const TEXT = 1;
	const BINARY = 2;
	const CLOSE = 8;
	const PING = 9;
	const PONG = 10;
	const MAX_FRAME = 16777216;

	private $sock;
	private $buf = '';
	private $frag = null;
	private $fragOp = 0;
	private $closed = false;
	private $sentClose = false;

	private function __construct($sock) {
		$this->sock = $sock;
	}

	public static function open($settings, $path, $token, $timeout = 20) {
		$base = csfm_normalize_url($settings['server_url'] ?? '');
		if ($base === false) {
			throw new CsfmHttpError('Server URL must be an https:// URL');
		}
		$u = parse_url($base);
		$host = $u['host'];
		$port = (int)($u['port'] ?? 443);
		$peer = trim($host, '[]');
		$pins = csfm_pins($settings['pin_sha256'] ?? '');
		$useCa = is_readable(CSFM_CA_FILE);
		$ssl = array(
			'verify_peer' => true,
			'verify_peer_name' => true,
			'peer_name' => $peer,
			'cafile' => $useCa ? CSFM_CA_FILE : CSFM_SYSTEM_CA_BUNDLE,
			'capture_peer_cert' => true,
			'SNI_enabled' => true,
			'disable_compression' => true,
		);
		if ($pins && !$useCa) {
			/* Self-issued server certificate: trust exactly the pinned key (checked below). */
			$ssl['verify_peer'] = false;
			$ssl['verify_peer_name'] = false;
			$ssl['allow_self_signed'] = true;
		}
		$ctx = stream_context_create(array('ssl' => $ssl));

		$proxy = csfm_cfg_get('system/proxyurl', '');
		$target = $proxy ? 'tcp://' . $proxy . ':' . ((int)csfm_cfg_get('system/proxyport', '') ?: 3128)
		    : "tcp://{$host}:{$port}";
		$sock = @stream_socket_client($target, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
		if (!$sock) {
			throw new CsfmHttpError("Could not reach the management server: {$errstr}");
		}
		stream_set_timeout($sock, $timeout);
		if ($proxy) {
			$req = "CONNECT {$host}:{$port} HTTP/1.1\r\nHost: {$host}:{$port}\r\n";
			$user = csfm_cfg_get('system/proxyuser', '');
			if ($user !== '') {
				$req .= 'Proxy-Authorization: Basic '
				    . base64_encode($user . ':' . csfm_cfg_get('system/proxypass', '')) . "\r\n";
			}
			fwrite($sock, $req . "\r\n");
			$status = self::readHead($sock)[0];
			if (!preg_match('#^HTTP/1\.[01] 200#', $status)) {
				throw new CsfmHttpError('The proxy refused the connection: ' . trim($status));
			}
		}
		$method = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
		if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
			$method |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
		}
		if (!@stream_socket_enable_crypto($sock, true, $method)) {
			$err = error_get_last();
			throw new CsfmHttpError('TLS connection to the management server failed' . ($err ? ': ' . $err['message'] : ''));
		}
		if ($pins) {
			$opts = stream_context_get_options($sock);
			$cert = $opts['ssl']['peer_certificate'] ?? null;
			if (!$cert || !in_array(csfm_spki_pin($cert), $pins, true)) {
				fclose($sock);
				throw new CsfmHttpError("The management server's key does not match the pinned key");
			}
		}

		$key = base64_encode(random_bytes(16));
		$hostHeader = ($port === 443) ? $host : "{$host}:{$port}";
		fwrite($sock, "GET /api/agent/v1{$path} HTTP/1.1\r\n"
		    . "Host: {$hostHeader}\r\n"
		    . "Upgrade: websocket\r\nConnection: Upgrade\r\n"
		    . "Sec-WebSocket-Key: {$key}\r\nSec-WebSocket-Version: 13\r\n"
		    . "Authorization: Bearer {$token}\r\n"
		    . 'User-Agent: comsense-agent/' . CSFM_AGENT_VERSION . "\r\n\r\n");
		list($status, $headers) = self::readHead($sock);
		if (!preg_match('#^HTTP/1\.1 101#', $status)) {
			fclose($sock);
			throw new CsfmHttpError('The server refused the terminal connection: ' . trim($status));
		}
		$accept = base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
		if (($headers['sec-websocket-accept'] ?? '') !== $accept) {
			fclose($sock);
			throw new CsfmHttpError('Bad WebSocket handshake from the server');
		}
		stream_set_blocking($sock, false);
		return new self($sock);
	}

	private static function readHead($sock) {
		$status = (string)fgets($sock, 4096);
		$headers = array();
		while (($line = fgets($sock, 8192)) !== false) {
			$line = rtrim($line, "\r\n");
			if ($line === '') {
				break;
			}
			$pos = strpos($line, ':');
			if ($pos !== false) {
				$headers[strtolower(trim(substr($line, 0, $pos)))] = trim(substr($line, $pos + 1));
			}
		}
		return array($status, $headers);
	}

	public function stream() {
		return $this->sock;
	}

	public function isClosed() {
		return $this->closed;
	}

	/* Messages received so far, as array(opcode, data); never blocks. */
	public function poll() {
		while (!$this->closed) {
			$chunk = @fread($this->sock, 65536);
			if ($chunk === false || $chunk === '') {
				if ($chunk === false || feof($this->sock)) {
					$this->closed = true;
				}
				break;
			}
			$this->buf .= $chunk;
		}
		$out = array();
		while (($f = $this->frame()) !== null) {
			list($fin, $op, $data) = $f;
			if ($op === self::PING) {
				$this->send(self::PONG, $data);
			} elseif ($op === self::CLOSE) {
				$this->closed = true;
				break;
			} elseif ($op === 0) {
				if ($this->frag !== null) {
					$this->frag .= $data;
					if ($fin) {
						$out[] = array($this->fragOp, $this->frag);
						$this->frag = null;
					}
				}
			} elseif ($op === self::TEXT || $op === self::BINARY) {
				if ($fin) {
					$out[] = array($op, $data);
				} else {
					$this->frag = $data;
					$this->fragOp = $op;
				}
			}
		}
		return $out;
	}

	private function frame() {
		$len = strlen($this->buf);
		if ($len < 2) {
			return null;
		}
		$b0 = ord($this->buf[0]);
		$b1 = ord($this->buf[1]);
		$n = $b1 & 0x7f;
		$off = 2;
		if ($n === 126) {
			if ($len < 4) {
				return null;
			}
			$n = unpack('n', substr($this->buf, 2, 2))[1];
			$off = 4;
		} elseif ($n === 127) {
			if ($len < 10) {
				return null;
			}
			$n = unpack('J', substr($this->buf, 2, 8))[1];
			$off = 10;
		}
		if ($n > self::MAX_FRAME) {
			$this->closed = true;
			return null;
		}
		$mask = null;
		if ($b1 & 0x80) {
			if ($len < $off + 4) {
				return null;
			}
			$mask = substr($this->buf, $off, 4);
			$off += 4;
		}
		if ($len < $off + $n) {
			return null;
		}
		$data = (string)substr($this->buf, $off, $n);
		$this->buf = (string)substr($this->buf, $off + $n);
		if ($mask !== null && $n > 0) {
			$data ^= substr(str_repeat($mask, intdiv($n, 4) + 1), 0, $n);
		}
		return array(($b0 & 0x80) !== 0, $b0 & 0x0f, $data);
	}

	public function send($op, $data) {
		if ($this->sock === null || ($this->closed && $op !== self::CLOSE)) {
			return false;
		}
		$n = strlen($data);
		$head = chr(0x80 | $op);
		if ($n < 126) {
			$head .= chr(0x80 | $n);
		} elseif ($n < 65536) {
			$head .= chr(0x80 | 126) . pack('n', $n);
		} else {
			$head .= chr(0x80 | 127) . pack('J', $n);
		}
		$mask = random_bytes(4);
		$body = $n ? ($data ^ substr(str_repeat($mask, intdiv($n, 4) + 1), 0, $n)) : '';
		return $this->writeAll($head . $mask . $body);
	}

	private function writeAll($bytes) {
		$deadline = microtime(true) + 30;
		while ($bytes !== '') {
			$w = @fwrite($this->sock, $bytes);
			if ($w === false) {
				$this->closed = true;
				return false;
			}
			if ($w > 0) {
				$bytes = (string)substr($bytes, $w);
				continue;
			}
			if (microtime(true) > $deadline) {
				$this->closed = true;
				return false;
			}
			$r = null;
			$wr = array($this->sock);
			$e = null;
			@stream_select($r, $wr, $e, 1);
		}
		return true;
	}

	public function close() {
		if ($this->sock === null) {
			return;
		}
		if (!$this->sentClose) {
			$this->sentClose = true;
			$this->send(self::CLOSE, pack('n', 1000));
		}
		@fclose($this->sock);
		$this->sock = null;
		$this->closed = true;
	}
}

/* The pins in the package settings, as bare base64 SHA-256 values. */
function csfm_pins($value) {
	$pins = array();
	foreach (preg_split('/[\s,;]+/', trim((string)$value)) as $pin) {
		if ($pin !== '') {
			$pins[] = (strpos($pin, 'sha256//') === 0) ? substr($pin, 8) : $pin;
		}
	}
	return $pins;
}

/* base64 SHA-256 of a certificate's SubjectPublicKeyInfo (the same pin curl checks). */
function csfm_spki_pin($cert) {
	$key = openssl_pkey_get_public($cert);
	if (!$key) {
		return '';
	}
	$pem = openssl_pkey_get_details($key)['key'] ?? '';
	$der = base64_decode(preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem));
	return base64_encode(hash('sha256', $der, true));
}

/* ------------------------------------------------------------- the session */

function csfm_terminal_request_file($sid) {
	return CSFM_TERM_DIR . '/' . $sid . '.request';
}

/* The shell, on a pseudo-terminal provided by script(1). */
function csfm_terminal_command($cols, $rows, $ttyFile) {
	$shell = is_executable('/bin/tcsh') ? '/bin/tcsh -l' : '/bin/sh -l';
	$inner = 'tty > ' . escapeshellarg($ttyFile) . '; stty rows ' . (int)$rows . ' columns ' . (int)$cols
	    . ' 2>/dev/null; cd; exec ' . $shell;
	if (PHP_OS_FAMILY === 'Linux') {
		/* util-linux script (the test harness). */
		return 'exec script -q -e -c ' . escapeshellarg($inner) . ' /dev/null';
	}
	return 'exec /usr/bin/script -q /dev/null /bin/sh -c ' . escapeshellarg($inner);
}

/* Set the window size; the kernel tells the shell's foreground job (SIGWINCH). */
function csfm_terminal_resize($ttyFile, $cols, $rows) {
	$tty = trim((string)@file_get_contents($ttyFile));
	if (!preg_match('#^/dev/(pts/)?[A-Za-z0-9]+$#', $tty)) {
		return false;
	}
	$flag = PHP_OS_FAMILY === 'Linux' ? '-F' : '-f';
	exec('/bin/stty ' . $flag . ' ' . escapeshellarg($tty) . ' rows ' . (int)$rows . ' columns ' . (int)$cols
	    . ' 2>/dev/null', $out, $rc);
	return $rc === 0;
}

/*
 * Run one terminal session (the "terminal" command). Returns a line for the
 * log. Exits when the shell ends, the server closes the session, or after
 * CSFM_TERM_MAX_SECONDS.
 */
function csfm_terminal_session($sid) {
	if (!preg_match(CSFM_TERM_SID_RE, $sid)) {
		return 'Invalid terminal session id';
	}
	$short = substr($sid, 0, 8);
	$settings = csfm_settings();
	if (empty($settings['enable']) || !csfm_is_enrolled()) {
		return 'The agent is not enrolled';
	}
	if (!csfm_has_capability('shell')) {
		return 'Remote terminal is not allowed in Services > ComSense Agent';
	}
	$creds = csfm_credentials();
	try {
		$ws = CsfmWebSocket::open($settings, '/terminal/' . $sid, $creds['token']);
	} catch (Exception $e) {
		csfm_log("Remote terminal {$short}: " . $e->getMessage(), LOG_WARNING);
		return $e->getMessage();
	}

	/* The server sends the browser's window size once both ends are connected. */
	$cols = 80;
	$rows = 24;
	$early = array();
	$deadline = time() + 150;
	$sized = false;
	while (!$sized && time() < $deadline && !$ws->isClosed()) {
		$r = array($ws->stream());
		$w = $e = null;
		@stream_select($r, $w, $e, 0, 250000);
		foreach ($ws->poll() as $msg) {
			$data = json_decode($msg[1], true);
			if (!is_array($data)) {
				continue;
			}
			if (($data['t'] ?? '') === 'r') {
				$cols = max(10, min(500, (int)($data['c'] ?? 80)));
				$rows = max(5, min(200, (int)($data['r'] ?? 24)));
				$sized = true;
			} elseif (($data['t'] ?? '') === 'i') {
				$early[] = (string)($data['d'] ?? '');
			}
		}
	}
	if (!$sized) {
		$ws->close();
		return 'The console did not connect';
	}

	csfm_ensure_db_dir();
	@mkdir(CSFM_TERM_DIR, 0700, true);
	$ttyFile = CSFM_TERM_DIR . '/' . $sid . '.tty';
	@unlink($ttyFile);
	$env = array(
		'TERM' => 'xterm-256color',
		'HOME' => '/root',
		'USER' => 'root',
		'LOGNAME' => 'root',
		'PATH' => '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
		'LANG' => 'C.UTF-8',
	);
	$proc = proc_open(csfm_terminal_command($cols, $rows, $ttyFile),
	    array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w')),
	    $pipes, is_dir('/root') ? '/root' : '/', $env);
	if (!is_resource($proc)) {
		$ws->send(CsfmWebSocket::TEXT, json_encode(array('t' => 'x', 'm' => 'Could not start a shell on the firewall.')));
		$ws->close();
		return 'Could not start a shell';
	}
	csfm_log("Remote terminal {$short} opened", LOG_NOTICE);
	stream_set_blocking($pipes[1], false);
	stream_set_blocking($pipes[2], false);
	foreach ($early as $keys) {
		fwrite($pipes[0], $keys);
	}

	$started = time();
	$reason = 'The session was closed.';
	$resize = null;
	$outputs = array(1 => $pipes[1], 2 => $pipes[2]);
	while (true) {
		$r = array_values($outputs);
		$r[] = $ws->stream();
		$w = $e = null;
		if (@stream_select($r, $w, $e, 0, 250000) === false) {
			$reason = 'The terminal helper failed.';
			break;
		}
		foreach ($outputs as $fd => $pipe) {
			$out = @fread($pipe, 65536);
			if ($out !== false && $out !== '') {
				$ws->send(CsfmWebSocket::BINARY, $out);
			} elseif (feof($pipe)) {
				fclose($pipe);
				unset($outputs[$fd]);
			}
		}
		if (!isset($outputs[1])) {
			$reason = 'The shell exited.';
			$ws->send(CsfmWebSocket::TEXT, json_encode(array('t' => 'x', 'm' => $reason)));
			break;
		}
		foreach ($ws->poll() as $msg) {
			if ($msg[0] !== CsfmWebSocket::TEXT) {
				continue;
			}
			$data = json_decode($msg[1], true);
			if (!is_array($data)) {
				continue;
			}
			if (($data['t'] ?? '') === 'i' && isset($data['d'])) {
				@fwrite($pipes[0], (string)$data['d']);
			} elseif (($data['t'] ?? '') === 'r') {
				$resize = array(max(10, min(500, (int)($data['c'] ?? 80))), max(5, min(200, (int)($data['r'] ?? 24))));
			}
		}
		if ($resize && csfm_terminal_resize($ttyFile, $resize[0], $resize[1])) {
			$resize = null;
		}
		if ($ws->isClosed()) {
			$reason = 'The management server closed the session.';
			break;
		}
		if (time() - $started > CSFM_TERM_MAX_SECONDS) {
			$reason = 'Time limit reached.';
			$ws->send(CsfmWebSocket::TEXT, json_encode(array('t' => 'x', 'm' => $reason)));
			break;
		}
	}
	$ws->close();
	@fclose($pipes[0]);
	foreach ($outputs as $pipe) {
		@fclose($pipe);
	}
	/* SIGHUP to script(1) hangs up the terminal, which ends the shell and its jobs. */
	proc_terminate($proc, 1);
	for ($i = 0; $i < 20 && proc_get_status($proc)['running']; $i++) {
		usleep(100000);
	}
	if (proc_get_status($proc)['running']) {
		proc_terminate($proc, 9);
	}
	proc_close($proc);
	@unlink($ttyFile);
	csfm_log("Remote terminal {$short} closed: {$reason}", LOG_NOTICE);
	return $reason;
}
