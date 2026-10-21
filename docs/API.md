# REST API and MCP server

ComSense can be driven by scripts and integrations (the REST API) and by AI assistants (the MCP
server). Both use **API keys** and do the same things with the same checks; the code is shared
(`server/app/services/apiops.py`).

## API keys

Create keys under **Settings > API keys** (admins). A key is shown once and stored only as a hash.
Send it on every request:

```
Authorization: Bearer csfm_api_...
```

| Key role | Can |
|---|---|
| viewer | read firewalls, customers, alerts, tasks, backups (metadata) and configurations |
| operator, admin | the same, and queue tasks on firewalls, acknowledge alerts, assign firewalls to customers |

Tasks follow the console's rules: the firewall's own permissions (Services > ComSense Agent) and the
server's `CSFM_ENABLE_FIREWALL_CHANGES` switch. Users, keys, settings, configurations and restores are
not available through keys. Keys can expire and be revoked; every change made with a key is in the
audit log as `api:<key name>`. Twenty failed keys from one address within five minutes block it for a
while.

## REST API

`https://<console address>/api/v1`, JSON. The OpenAPI description is at `/api/v1/openapi.json`.

| Method | Path | |
|---|---|---|
| GET | `/firewalls?customer_id=&status=&search=&agent_outdated=` | Firewalls, by customer then name |
| GET | `/firewalls/{id}` | One firewall with interfaces, gateways, services, packages, metrics |
| GET | `/firewalls/{id}/tasks?limit=` | Recent tasks |
| POST | `/firewalls/{id}/tasks` | Queue a task: `{"task": "backup"}` (operator) |
| PUT | `/firewalls/{id}/customer` | `{"customer_id": 3}` or `{"customer_id": null}` (operator) |
| GET | `/firewalls/{id}/backups` | Stored configuration backups (metadata) |
| GET | `/tasks/{id}` | One task with its status and output |
| GET | `/tasks-available` | The task names `POST /firewalls/{id}/tasks` accepts |
| GET | `/customers`, `/customers/{id}` | Customers; one customer with its firewalls |
| GET | `/alerts?open_only=&firewall_id=&limit=` | Alerts, newest first, with their category (system, wan, down, services, resources) |
| POST | `/alerts/{id}/acknowledge` | Acknowledge (operator) |
| GET | `/configurations` | Configurations (policies) |

Tasks: `check_now`, `backup`, `check_updates`, `update_agent`, `upgrade_packages`, `upgrade_system`
(reboots), `reboot`, `restart_service` (with `service`), `install_package` and `remove_package` (with
`package`, `pfSense-pkg-...`). A task is queued and runs on the firewall within seconds to minutes;
follow it with `GET /tasks/{id}`.

```sh
KEY=csfm_api_...
curl -H "Authorization: Bearer $KEY" https://comsense.example.com/api/v1/firewalls?agent_outdated=true
curl -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
     -d '{"task":"backup"}' https://comsense.example.com/api/v1/firewalls/<id>/tasks
```

Errors are `{"detail": "..."}` with 400 (bad request), 401 (no or bad key), 403 (the key's role is not
enough), 404, 409 (refused, e.g. the firewall does not allow it) or 429.

## MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server on its own port: Streamable HTTP at
`/mcp`, stateless, with the API key as a bearer token. Its tools: `list_firewalls`, `get_firewall`,
`list_customers`, `get_customer`, `list_alerts`, `acknowledge_alert`, `list_tasks`, `get_task`,
`run_task`, `list_backups`, `assign_customer`, `list_configurations`. Read tools are marked read only;
`run_task` is marked destructive, so assistants ask before rebooting or upgrading.

| Setting | Default | |
|---|---|---|
| `CSFM_MCP_PORT` | 8090 | Port of the MCP server; `0` turns it off |
| `CSFM_MCP_HOST` | 127.0.0.1 (Docker: 0.0.0.0) | Address it listens on |

Like the console it speaks plain HTTP, so publish it through HTTPS:

* **Docker with Caddy** (`docker-compose.caddy.yml`): Caddy serves it at `https://<CSFM_DOMAIN>:8443/mcp`
  (`CSFM_MCP_PORT_PUBLIC` changes the port).
* **Your own proxy** (`docker-compose.byo-proxy.yml`): published on `CSFM_WEB_BIND:8090`
  (`CSFM_MCP_PORT_PUBLIC`); add a proxy host for it with HTTPS, as for the console.

An MCP client is configured with the URL and the key, e.g. for clients that take a JSON config:

```json
{
  "mcpServers": {
    "comsense": {
      "type": "http",
      "url": "https://comsense.example.com:8443/mcp",
      "headers": { "Authorization": "Bearer csfm_api_..." }
    }
  }
}
```

Give an assistant a viewer key unless it should act on firewalls.
