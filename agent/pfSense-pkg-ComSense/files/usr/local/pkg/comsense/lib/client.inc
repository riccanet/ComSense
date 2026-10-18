<?php
/*
 * ComSense agent - HTTPS client for the management server.
 *
 * Every request goes over HTTPS with full certificate and hostname
 * verification. Plain HTTP URLs are refused. Optionally the server's CA can be
 * supplied (for a private PKI) and its public key pinned.
 */

require_once(__DIR__ . '/common.inc');

class CsfmHttpError extends Exception {
	public $status;
	public $body;

	public function __construct($message, $status = 0, $body = null) {
		parent::__construct($message);
		$this->status = $status;
		$this->body = $body;
	}
}

class CsfmClient {
	private $base;
	private $token;
	private $settings;

	public function __construct($settings, $token = null) {
		$base = csfm_normalize_url($settings['server_url'] ?? '');
		if ($base === false) {
			throw new CsfmHttpError('Server URL must be an https:// URL');
		}
		$this->base = $base . '/api/agent/v1';
		$this->token = $token;
		$this->settings = $settings;
	}

	public function setToken($token) {
		$this->token = $token;
	}

	public function postJson($path, $data, $timeout = 60) {
		$body = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
		list($status, $resp) = $this->request('POST', $path, $body, array('Content-Type: application/json'), $timeout);
		return $this->decode($status, $resp);
	}

	public function getJson($path, $timeout = 30) {
		list($status, $resp) = $this->request('GET', $path, null, array(), $timeout);
		return $this->decode($status, $resp);
	}

	public function postRaw($path, $bytes, $headers, $timeout = 300) {
		list($status, $resp) = $this->request('POST', $path, $bytes, $headers, $timeout);
		return $this->decode($status, $resp);
	}

	/* Returns array(body, response headers). */
	public function download($path, $timeout = 300) {
		$headers = array();
		list($status, $resp) = $this->request('GET', $path, null, array(), $timeout, $headers);
		if ($status !== 200) {
			$this->decode($status, $resp);
		}
		return array($resp, $headers);
	}

	private function decode($status, $resp) {
		$data = json_decode((string)$resp, true);
		if ($status < 200 || $status >= 300) {
			$detail = is_array($data) && isset($data['detail']) ? $data['detail'] : substr((string)$resp, 0, 200);
			if (is_array($detail)) {
				$detail = json_encode($detail);
			}
			throw new CsfmHttpError("Server returned HTTP {$status}: {$detail}", $status, $data);
		}
		if (!is_array($data)) {
			throw new CsfmHttpError('Server returned a response that is not JSON', $status);
		}
		return $data;
	}

	private function request($method, $path, $body, $headers, $timeout, &$respHeaders = null) {
		$ch = curl_init($this->base . $path);
		$headers[] = 'Accept: application/json';
		$headers[] = 'User-Agent: comsense-agent/' . CSFM_AGENT_VERSION;
		if ($this->token) {
			$headers[] = 'Authorization: Bearer ' . $this->token;
		}
		$opts = array(
			CURLOPT_CUSTOMREQUEST => $method,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER => $headers,
			CURLOPT_CONNECTTIMEOUT => 15,
			CURLOPT_TIMEOUT => $timeout,
			CURLOPT_FOLLOWLOCATION => false,
			CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
			CURLOPT_SSL_VERIFYPEER => true,
			CURLOPT_SSL_VERIFYHOST => 2,
			CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
			CURLOPT_CAINFO => is_readable(CSFM_CA_FILE) ? CSFM_CA_FILE : CSFM_SYSTEM_CA_BUNDLE,
		);
		if (!empty($this->settings['pin_sha256']) && !is_readable(CSFM_CA_FILE)) {
			/*
			 * The server issued its own certificate: trust exactly the pinned
			 * public key instead of a certificate authority. curl enforces the
			 * pin even with chain verification off, so any other key is refused.
			 */
			$opts[CURLOPT_SSL_VERIFYPEER] = false;
			$opts[CURLOPT_SSL_VERIFYHOST] = 0;
		}
		if (!empty($this->settings['pin_sha256'])) {
			$pins = array();
			foreach (preg_split('/[\s,;]+/', trim($this->settings['pin_sha256'])) as $pin) {
				if ($pin !== '') {
					$pins[] = (strpos($pin, 'sha256//') === 0) ? $pin : 'sha256//' . $pin;
				}
			}
			$opts[CURLOPT_PINNEDPUBLICKEY] = implode(';', $pins);
		}
		if ($body !== null) {
			$opts[CURLOPT_POSTFIELDS] = $body;
		}
		$this->applyProxy($opts);
		$captured = array();
		$opts[CURLOPT_HEADERFUNCTION] = function ($ch, $line) use (&$captured) {
			$pos = strpos($line, ':');
			if ($pos !== false) {
				$captured[strtolower(trim(substr($line, 0, $pos)))] = trim(substr($line, $pos + 1));
			}
			return strlen($line);
		};
		curl_setopt_array($ch, $opts);
		$resp = curl_exec($ch);
		if ($resp === false) {
			$err = curl_error($ch);
			curl_close($ch);
			throw new CsfmHttpError("Could not reach the management server: {$err}");
		}
		$status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
		curl_close($ch);
		$respHeaders = $captured;
		return array($status, $resp);
	}

	/* Honour the proxy configured under System > Advanced > Miscellaneous. */
	private function applyProxy(&$opts) {
		$url = csfm_cfg_get('system/proxyurl', '');
		if (empty($url)) {
			/* Ignore *_proxy environment variables; only the pfSense setting counts. */
			$opts[CURLOPT_PROXY] = '';
			return;
		}
		$opts[CURLOPT_PROXY] = $url;
		$port = csfm_cfg_get('system/proxyport', '');
		if (!empty($port)) {
			$opts[CURLOPT_PROXYPORT] = (int)$port;
		}
		$user = csfm_cfg_get('system/proxyuser', '');
		if (!empty($user)) {
			$opts[CURLOPT_PROXYUSERPWD] = $user . ':' . csfm_cfg_get('system/proxypass', '');
		}
	}
}

function csfm_client() {
	$creds = csfm_credentials();
	return new CsfmClient(csfm_settings(), $creds['token'] ?? null);
}
