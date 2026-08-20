# claude-project — netmiko MCP server + skill

A ready-to-copy project that gives an AI agent **read-only access to routers,
switches and firewalls over SSH**, through the Model Context Protocol.

It ships two pieces and the wiring between them:

- **`mcps/mcp_server_netmiko.py`** — a self-contained MCP server. Ten tools,
  every command validated against an operator-defined allow/deny list, output
  parsed into JSON with `ntc-templates`, and a fail-closed audit trail of every
  attempt.
- **`.claude/skills/netmiko/SKILL.md`** — the skill that teaches the agent when
  to reach for those tools, what the per-platform CLI dialects look like, and how
  to read a refusal.

Nothing here writes to a device. The allow list is default-deny — an empty one
permits nothing — and the deny side always wins over the allow side.

Everything that happens goes into an audit trail, and `netmiko.query_audit_trail`
makes it answerable in conversation: *"everything done on SW-CORE-01, by date"*,
*"the last 6 actions"*, *"which commands were refused this week"*. With no UI in
this project, that tool is the only way to read it.

## Authors and provenance

**This project is authored by Ed Scrimaglia** — <edgardo.scrimaglia@gmail.com>,
[Octupus](https://octupus.com). Server, skill, configuration model and
documentation are his work, written for the **Niko agent** and packaged here as a
standalone project.

It began from a fork, and that origin is acknowledged rather than hidden: the
starting point was **Kirk Byers'** work, and the project grew well past it. What
is here now — the source-of-truth-backed inventory, credential resolution, the
three deployment flavors, output paging, the audit trail, the skill and this
documentation — did not come from upstream.

The two upstream projects by **Kirk Byers**:

- [**Netmiko**](https://github.com/ktbyers/netmiko) — the multi-vendor SSH
  library that does the actual talking to the devices.
- [**netmiko_mcp**](https://github.com/ktbyers/netmiko_mcp) — the MCP server this
  one was forked from. One part of it survives largely as it was: the security
  core (command validation, glob handling, the allow/deny asymmetry), kept a
  faithful port on purpose so that upstream patches can still be diffed in. That
  was an engineering decision, not a limit on the rest of the work.

## About Niko

This server was written for **Niko**, Neural Intelligence Knowledge Orchestrator AI agent built by Ed Scrimaglia at 
Octupus. Niko fronts a set of MCP servers — the source-of-truth server, this one, Jira, send emails, create files 
and others — so that an operator can ask a question in plain language and have it
answered from the real estate: the SoT for what *should* be true, the devices
themselves for what *is*.

Inside Niko the same file runs a little differently, and that is worth knowing
because it explains a few things in the code:

- Servers run **over HTTP on loopback**, one port each, declared in
  `mcps/mcp_config.json` with `url` / `transport` / `local` / `env` — the same
  two-axis configuration described below, expressed in Niko's own format.
- Installation goes through the app, not by copying files: the upload is
  validated, the dependencies are resolved out of the code itself, and a failed
  install rolls back instead of leaving half a server behind.

Every one of those integrations is an **optional import with a fallback**, so
`niko` never has to be installed. There are four, and this is what each degrades
to when the import fails:

| Import | Line | Standalone fallback |
|---|---|---|
| `niko.srvclass_logging.MCPLogging` | 60 | `NIKO_AVAILABLE = False`; the server configures its own `logging` |
| `niko.niko_paths.NikoPaths` | 68 | `None`; paths come from the `NETMIKO_MCP_*` variables, which is why this project sets them explicitly |
| `niko.srvclass_logging.SyncedConcurrentTimedRotatingFileHandler` | 436 | `FailClosedFileHandler` — still fail-closed, just not multi-process-safe |
| `niko.srvclass_list_budget.apply_budget_to_payload` | 2709 | a no-op that returns the payload unchanged |

Nothing is lost that matters outside Niko: the concurrent handler solves a
several-processes-one-file problem that does not arise here, and the list budget
trims long payloads for an agent that has its own context accounting. One file,
two homes, no fork.

`Fedele` is Niko's source of truth, which is why the SoT variables carry the
`FEDELE_` prefix even when they point at a NetBox instance.

## License

This project's own code is **MIT** — see [`LICENSE`](LICENSE).

It is a derivative work, so two licenses apply and both files ship with it:

| | License | File |
|---|---|---|
| This project's code, docs and skill | MIT | [`LICENSE`](LICENSE) |
| Portions ported from `ktbyers/netmiko_mcp` | Apache-2.0 | [`LICENSE-APACHE-2.0`](LICENSE-APACHE-2.0) |

[`NOTICE`](NOTICE) carries the attribution and the statement of modifications
that Apache-2.0 §4(b) requires. Netmiko is an ordinary MIT dependency: imported,
not vendored, nothing to redistribute.

---

## Layout

```
claude-project/
├── .mcp.json                     # declares the server (project scope)
├── .env.example                  # → copy to .env with the SSH credentials
├── .claude/skills/netmiko/
│   └── SKILL.md                  # one directory per skill, file named SKILL.md
├── mcps/
│   └── mcp_server_netmiko.py     # NOT at the root: the server reads ../.env
├── config/netmiko/
│   ├── commands.yml              # allow/deny list — without it, a 16-command fallback applies
│   └── inventory.yml             # inventory in netmiko_tools format
├── logs/                         # netmiko-mcp.log + netmiko-audit.jsonl
├── mcpr/netmiko/                 # created on demand (0700): large outputs
├── LICENSE  LICENSE-APACHE-2.0  NOTICE
└── pyproject.toml
```

Two rules that are not negotiable:

1. **The skill lives in `.claude/skills/<name>/SKILL.md`.** Claude Code does not
   read `skills/netmiko.md`: it needs the directory and that exact file name.
2. **The server lives in `mcps/`, not at the root.** `PARENT_DIR` is the parent
   of the directory holding the `.py` (`mcp_server_netmiko.py:62`), and that is
   where the `.env` comes from. With the server at the root, the `.env` would be
   looked up one level above the project.

## Getting it running

```bash
uv venv --python 3.12
uv pip install -r <(uv pip compile pyproject.toml)   # or: uv sync
cp .env.example .env && $EDITOR .env                 # SSH credentials
# .mcp.json needs no editing: its paths are project-relative
claude                                               # approve the project server
```

Inside the session: `/mcp` lists the 10 tools, `/skills` confirms the skill was
loaded. First check, without touching the network:

> which command policy is the netmiko MCP enforcing?

---

# The three flavors

Where the **inventory** comes from and where the **credentials** come from are
two independent axes. That is what makes three deployments out of one server —
and the reason the server never has to be modified to move between them: two
environment variables decide.

| | Inventory | Credentials | What you need | When to use it |
|---|---|---|---|---|
| **A — SoT everything** | Fedele | Fedele | API token + Fernet key | The SoT is authoritative and already holds the device credentials |
| **B — SoT inventory, local credentials** | Fedele or NetBox | `.env` | API token | You have a SoT but not its credential plugin. **The usual starting point** |
| **C — Self-contained** | local YAML | `.env` | nothing external | Lab, air-gapped, a demo, or degraded mode when the SoT is down |

`netmiko.get_metadata` reports which one is actually running — never assume from
the config file:

```json
{
  "inventory": {"backend": "fedele", "scope_filter": {"tag": "lab"}, "available": true},
  "credential_source": "env",
  "device_types_in_inventory": ["cisco_ios", "huawei_vrp", "…"]
}
```

## A — Fedele as the source of truth, credentials included

The agent asks for a device by **name**; the server resolves address, platform
and credentials against the SoT at call time. Nothing about the estate lives in
this project: add a device to the SoT and it is reachable on the next call, with
no file to edit and no restart.

```jsonc
// .mcp.json → env
"NETMIKO_MCP_INVENTORY_TYPE": "fedele",
"NETMIKO_MCP_CREDENTIAL_SOURCE": "fedele",
"NETMIKO_MCP_FEDELE_GROUP_SOURCE": "tags",        // tags | device_roles | sites
"NETMIKO_MCP_FEDELE_DEVICE_FILTER": "tag=lab",    // the scope filter — read the warning
"NETMIKO_MCP_FEDELE_CACHE_TTL": "60"
```

```bash
# .env
FEDELE_URL=https://fedele.example.com
FEDELE_TOKEN=<API token>
FEDELE_CREDENTIALS_KEY=<Fernet key of the fedele_credentials plugin>
```

Files: none are mandatory. `commands.yml` is *recommended* — without it the
built-in [fallback policy](#commandsyml-is-recommended-not-required) applies. No
local inventory is involved, and no `NETMIKO_USERNAME` / `NETMIKO_PASSWORD`;
with `credential_source=fedele`, `NETMIKO_SECRET` is **ignored** — the enable
password comes from the SoT too.

How the credential lookup works, three hops:

```
GET dcim/devices/?name=<name>                          → device.id
GET plugins/credentials/devicecredentials/?device=<id> → credential id
GET plugins/credentials/networkcredentials/<id>/       → username + encrypted password
                                                          decrypted locally with the Fernet key
```

Things worth knowing before you pick this flavor:

- **The Fernet key is the whole security boundary.** It decrypts device
  passwords in the server's memory. Treat it like the passwords themselves.
- Without `FEDELE_CREDENTIALS_KEY` the server still starts, and **every** tool
  returns the same `Startup Error` naming the missing variable. It fails loudly,
  not silently.
- **Set the scope filter.** Without `NETMIKO_MCP_FEDELE_DEVICE_FILTER` the
  inventory is the entire estate the SoT knows about, which is also the entire
  set of devices the agent can reach. The server logs a warning when it is
  missing; the filter takes query syntax, `tag=lab&status=active`.
- A device without a `primary_ip`, without a `platform`, or whose platform is
  not a Netmiko `device_type` is **excluded** from the inventory — SoTs also
  inventory cameras, badge readers and chassis. Exclusions are counted and
  reported, so the agent never claims "these are all the devices" over a subset.
- There is a circuit breaker: after a transport error or a 5xx the client stops
  calling the SoT for 30 s. A group command against 40 devices with the SoT down
  fails once, not forty times.

## B — SoT for the inventory, credentials in the `.env`

Identical to A with one variable flipped:

```jsonc
"NETMIKO_MCP_CREDENTIAL_SOURCE": "env",
```

```bash
# .env
FEDELE_URL=https://sot.example.com
FEDELE_TOKEN=<API token>
NETMIKO_USERNAME=<service account>
NETMIKO_PASSWORD=<password>
NETMIKO_SECRET=<enable password, if any device asks for it>
```

You get the dynamic inventory — the part that pays for itself — without the
credential plugin and without the Fernet key. One service account is used for
every device.

### NetBox, or any NetBox-shaped SoT

The inventory backend speaks the NetBox REST dialect, so **NetBox itself works
in this flavor**, unmodified:

| What the backend calls | What it reads |
|---|---|
| `dcim/devices/` | the device list, filtered by the scope filter and paginated |
| `extras/tags/`, `dcim/device-roles/`, `dcim/sites/` | whichever one `FEDELE_GROUP_SOURCE` selects becomes the device groups |
| `device.primary_ip.address` | the SSH host, mask stripped |
| `device.platform.name` | the Netmiko `device_type`, validated against `CLASS_MAPPER` |

Point `FEDELE_URL` at the NetBox instance (`/api` is appended if you leave it
off) and `FEDELE_TOKEN` at a NetBox API token — the client authenticates with the
`Authorization: Token …` header NetBox expects. The variables keep the `FEDELE_`
prefix; that is a naming legacy, not a product requirement.

The one requirement NetBox does not satisfy by default: **`platform.name` must
be exactly a Netmiko `device_type`** — `cisco_ios`, `arista_eos`, `huawei_vrp`,
`juniper_junos`. A platform named "Cisco IOS 15.2" is not a device_type, so
every device carrying it is excluded from the inventory. Either rename the
platforms in NetBox or accept the exclusions, which are reported.

Credentials are the part NetBox does **not** cover: the
`plugins/credentials/…` endpoints belong to Fedele's plugin. With plain NetBox,
flavor A is not available — stay on B.

## C — Self-contained: no SoT at all

Everything lives in this project. No external service is contacted, ever.

```jsonc
// .mcp.json → env
"NETMIKO_MCP_INVENTORY_TYPE": "yaml",
"NETMIKO_MCP_CREDENTIAL_SOURCE": "env",
"NETMIKO_MCP_INVENTORY_FILE": "/abs/path/claude-project/config/netmiko/inventory.yml"
```

```bash
# .env
NETMIKO_USERNAME=<service account>
NETMIKO_PASSWORD=<password>
NETMIKO_SECRET=<enable password, if any device asks for it>
```

Files: `inventory.yml` is **required** here — it is the only place the devices
exist. `commands.yml` remains recommended, not required. The inventory is the
`netmiko_tools` format — a flat mapping of name to connection data, plus group
keys:

```yaml
CORE-RTR-01:
  device_type: cisco_xr        # must be a Netmiko device_type, verbatim
  host: 192.0.2.11

CORE-SW-01:
  device_type: arista_eos
  host: 192.0.2.21

core:                          # a group is a list of device names
- CORE-RTR-01
- CORE-SW-01
```

The file this project ships is example data: 12 fictional devices on the RFC 5737
documentation ranges, 7 groups, and platforms picked so that every CLI dialect the
allow list mentions is represented. Replace it with your own estate.

This is **the flavor this project ships configured**, and it is also **degraded
mode**: if the SoT goes down, two variables and a restart move a flavor-A or
flavor-B deployment here. That is worth rehearsing before you need it.

The cost is that the file goes stale. `scripts/export_inventory.py` in the
parent repository regenerates it from the SoT; run it on a schedule. A backup
inventory carrying addresses from six months ago is worse than no backup at all,
because you find out while operating.

### What stays the same in all three

The command policy, the audit trail, the output paging and the tool surface do
not change between flavors. The agent-facing contract is identical, which is why
the skill needs no per-flavor variant.

### `commands.yml` is recommended, not required

The server runs without it. If the file is missing it does **not** deny
everything and it does **not** refuse to start: a built-in fallback of 16
read-only commands takes over — `show version`, `show ip interface brief`,
`display version` and their Junos/VRP equivalents. That is deliberate. An empty policy would deny every
command while the server still reported itself healthy, which reads to an
operator as "the device refused" rather than "nobody wrote a policy". The
fallback is announced at startup, `netmiko.get_command_policy` reports
`policy_source: "fallback"`, and every audited attempt carries the source.

So the file is a *policy decision*, not an installation step: the fallback lets
you run the server on the first try, and you write `commands.yml` when you want
the estate's own policy instead of a conservative default. What you cannot do is
have a policy you did not choose and not know it — the server says which one is
in force, every time it is asked.

---

# The `.mcp.json` file

`.mcp.json` at the project root declares the MCP servers **for this project**.
Claude Code asks for approval the first time it sees the file, and the file is
meant to be committed: it is how the whole team gets the same server.

Two other scopes exist for the same server definition:

| Scope | Where it lives | Who sees it |
|---|---|---|
| `project` | `.mcp.json` at the project root | anyone who opens the project (after approving it) |
| `user` | `~/.claude.json` | every project of that user, on that machine |
| `local` | `~/.claude.json`, keyed by project path | only that user, only in that project |

`claude mcp add --scope project netmiko -- /path/to/python /path/to/server.py`
writes the `project` entry for you; editing the JSON by hand is equivalent.

## Shape of the file

```jsonc
{
  "mcpServers": {           // ← the top-level key. Not "servers", not "mcp".
    "netmiko": {            // ← the server name; it becomes the tool prefix
      ...                   //    mcp__netmiko__<tool>
    }
  }
}
```

The server name is not cosmetic: Claude Code exposes each tool as
`mcp__<server-name>__<tool-name>`. With the name `netmiko` and the tool
`netmiko.get_metadata` that the server registers, the tool Claude actually sees
is `mcp__netmiko__netmiko.get_metadata`. Run `/mcp` to read the exact names
before writing them into an `allowed-tools` list or a permission rule.

## Field reference

| Field | Transport | Meaning |
|---|---|---|
| `type` | both | `"stdio"` (default when omitted), `"http"`, or `"sse"` |
| `command` | stdio | the executable to spawn. Absolute path — do not assume a cwd |
| `args` | stdio | argument list, each element separate |
| `env` | stdio | environment for the child process. Merged on top of the inherited one |
| `url` | http / sse | full endpoint URL, including the path |
| `headers` | http / sse | extra request headers, typically `Authorization` |

Values support environment expansion: `${VAR}` and `${VAR:-default}`. Useful for
keeping a token out of the committed file:

```jsonc
"headers": { "Authorization": "Bearer ${NETMIKO_MCP_TOKEN}" }
```

## Transport 1 — stdio (the one this project uses)

Claude Code spawns the server as a child process and speaks JSON-RPC over its
stdin/stdout. Nothing listens on a port, nothing is reachable from the network,
and the process lifetime is the session's. This is the right default for a
server that holds SSH credentials.

```json
{
  "mcpServers": {
    "netmiko": {
      "type": "stdio",
      "command": "${CLAUDE_PROJECT_DIR:-.}/.venv/bin/python",
      "args": ["${CLAUDE_PROJECT_DIR:-.}/mcps/mcp_server_netmiko.py"],
      "env": {
        "NETMIKO_MCP_INVENTORY_TYPE": "yaml",
        "NETMIKO_MCP_INVENTORY_FILE": "${CLAUDE_PROJECT_DIR:-.}/config/netmiko/inventory.yml",
        "NETMIKO_MCP_COMMAND_FILE": "${CLAUDE_PROJECT_DIR:-.}/config/netmiko/commands.yml",
        "NETMIKO_MCP_CREDENTIAL_SOURCE": "env",
        "NETMIKO_MCP_SAVE_OUTPUT_DIR": "${CLAUDE_PROJECT_DIR:-.}/mcpr/netmiko",
        "NETMIKO_MCP_AUDIT_LOG_FILE": "${CLAUDE_PROJECT_DIR:-.}/logs/netmiko-audit.jsonl",
        "LOG_FILE": "${CLAUDE_PROJECT_DIR:-.}/logs/netmiko-mcp.log",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

Two things that bite:

- **No hard-coded paths**, and the working directory is not something to rely
  on. `${CLAUDE_PROJECT_DIR:-.}` is what keeps the file committable as-is; the
  next section is the whole story, because the obvious reading of it is wrong.
- **The server must not write to stdout.** stdout *is* the protocol channel, and
  one stray line there breaks the session. Logging goes to stderr plus the
  rotating file at `LOG_FILE` (5 MB × 3, created `0600` — at `DEBUG` this file
  carries device output). Inside Niko the same variable is handled by
  `MCPLogging` instead.

### Where `${CLAUDE_PROJECT_DIR:-.}` comes from

Two separate things in one string: a syntax and a variable.

**The syntax.** `${VAR}` and `${VAR:-default}` is POSIX parameter substitution
("use `VAR`; if it is unset or empty, use `default`"), but no shell is involved
— a JSON file never passes through one. Claude Code implements the expansion
itself when it reads the file, in `command`, `args`, `env`, `url` and `headers`.
It is a convention of *that client*, not part of the MCP specification: another
client may not implement it (see [Non-Claude agents](#non-claude-agents), where
the paths then have to be literal), and VS Code has its own spelling,
`${workspaceFolder}`.

**The variable.** `CLAUDE_PROJECT_DIR` is set by Claude Code to the project
root, the same value hooks receive. It is stable — granting extra working
directories mid-session with `--add-dir` does not move it.

**The part that is counterintuitive**, and the reason the `:-.` is not
decoration: Claude Code sets that variable **in the environment of the server it
spawns, not in its own**. The expansion, though, happens *before* the spawn,
against Claude Code's environment — where the variable does not exist. A bare
`${CLAUDE_PROJECT_DIR}` would therefore expand to nothing and leave
`/config/netmiko/inventory.yml`, an absolute path to the root of the filesystem.

So in a project-scoped `.mcp.json` the default is not a fallback for some edge
case: **it is the value that is used, every time.** What reaches the process is
`./config/netmiko/inventory.yml`. The one exception is an MCP config shipped by
a plugin — there Claude Code substitutes the variable directly and no default is
needed.

That is what forces the server's hand. A relative value would resolve against
the cwd of the child process, and the cwd is the client's choice, not the
project's. Hence `resolve_project_path()`: every relative path setting is
anchored to `PARENT_DIR` — the parent of `mcps/`, the same root the `.env` comes
from — when the settings load. A session launched from anywhere finds
`config/netmiko/`, and `validate_startup()` names the absolute file when one is
missing. A `~` still means the operator's home, never a file inside the project.

The variable is still useful the way the documentation intends, read from
*inside* the server (`os.environ["CLAUDE_PROJECT_DIR"]`), where it is set. This
server does not need it: `PARENT_DIR` derives from `__file__` and so depends on
no client at all — the same reason the HTTP transport, where nobody sets that
variable, needs no special case.

Source: [Claude Code — MCP](https://code.claude.com/docs/en/mcp), sections *Add
a local stdio server* and *Environment variable expansion in `.mcp.json`*.

## Transport 2 — HTTP (streamable HTTP)

Claude Code supports it, and so does any other MCP client. It is the transport
to use when the server runs somewhere else: another host, a container, a service
shared by several agents, or an agent that is not Claude.

The server file always calls `mcp.run(transport="stdio")` under its `__main__`
guard, so HTTP is served by the FastMCP CLI instead — no code change:

```bash
.venv/bin/fastmcp run mcps/mcp_server_netmiko.py \
  --transport http --host 127.0.0.1 --port 8123
# endpoint: http://127.0.0.1:8123/mcp
```

The path has no trailing slash: `/mcp` is the route FastMCP registers, and
`/mcp/` answers `307` to it. Clients follow the redirect, so an old config with
the slash still works — it just pays a round trip on every request.

The `NETMIKO_MCP_*` variables are no longer part of the client config: the
server process is started by you, so they belong to *its* environment (a shell
export, a systemd unit, a container's `environment:` block).

Client side:

```json
{
  "mcpServers": {
    "netmiko": {
      "type": "http",
      "url": "http://127.0.0.1:8123/mcp",
      "headers": {
        "Authorization": "Bearer ${NETMIKO_MCP_TOKEN}"
      }
    }
  }
}
```

Or, equivalently, `claude mcp add --transport http netmiko http://127.0.0.1:8123/mcp`.

`--transport sse` and `"type": "sse"` also work; SSE is the older remote
transport and is kept for clients that have not moved to streamable HTTP.

> **Security.** The FastMCP CLI serves this without any authentication: whoever
> reaches the port can run show commands against every device in the inventory,
> using the credentials in the server's environment. Bind to `127.0.0.1` for a
> local test, and for anything shared put it behind a reverse proxy that
> terminates TLS and checks the `Authorization` header. The `headers` block
> above is what the client sends; the proxy is what has to verify it.
>
> Binding to loopback is not by itself enough, which is why the server sets
> `http_host_origin_protection = "auto"` at import (§1). A page open in your
> browser can point its own domain at `127.0.0.1` and reach the port: to the
> browser that is same-origin, so no CORS applies and its JavaScript reads the
> response — needing no credentials, since the server holds them and asks the
> client for nothing. The foreign `Host` header is the only trace it leaves. With
> the guard on, a foreign `Host` gets **421** and a foreign `Origin` gets **403**,
> while a legitimate localhost request is served. It costs nothing client-side: a
> non-browser client sends no `Origin` at all, so that half is never evaluated.
>
> The server also sets `stateless_http` and `json_response` to `True`, so each
> request stands alone and is answered with a single `application/json` body
> instead of an SSE stream. Both are `False` by default in FastMCP.

## Non-Claude agents

The `mcpServers` object shown here is the de facto shape: Claude Code, Claude
Desktop, Cursor and Windsurf all read the same three fields for stdio
(`command` / `args` / `env`) and the same two for remote (`url` / `headers`).
Copying an entry between them normally works as-is.

Known differences worth checking before you copy:

- **VS Code** uses `mcp.json` with a top-level `"servers"` key instead of
  `"mcpServers"`, and it wants `"type"` stated explicitly.
- Some clients do not implement `${VAR}` expansion; there the value has to be
  literal, which is an argument for the HTTP transport plus a proxy rather than
  a token pasted into a committed file.
- An agent with no config file at all can still speak to the HTTP endpoint
  directly — the URL and the `Authorization` header are the entire contract.

## The `env` block

The `NETMIKO_MCP_*` entries win over any YAML config file. They are set
explicitly because outside Niko there is no `NikoPaths`, so the defaults fall
back to `~/commands.yml` and `~/.netmiko_mcp_tmp`.

Every path here may be written relative to the project root: the server anchors
relative values to `PARENT_DIR` when the settings load, so the cwd of the
spawned process never decides where the inventory or the audit trail lives. An
absolute path or a `~` is taken as written.

| Variable | Default | Purpose |
|---|---|---|
| `NETMIKO_MCP_INVENTORY_TYPE` | `netmiko_tools` | `yaml` (local file) or `fedele` (SoT) |
| `NETMIKO_MCP_INVENTORY_FILE` | *(netmiko-tools lookup)* | inventory path when the type is `yaml` |
| `NETMIKO_MCP_CREDENTIAL_SOURCE` | `env` | `env` (reads the `.env`) or `fedele` |
| `NETMIKO_MCP_FEDELE_GROUP_SOURCE` | `tags` | what defines a group: `tags`, `device_roles`, `sites` |
| `NETMIKO_MCP_FEDELE_DEVICE_FILTER` | *(none)* | scope filter, `tag=lab&status=active`. Without it: the whole estate |
| `NETMIKO_MCP_FEDELE_CACHE_TTL` | `60` | SoT resolution cache, in seconds |
| `NETMIKO_MCP_COMMAND_FILE` | `~/commands.yml` outside Niko | allow/deny list |
| `NETMIKO_MCP_ALLOW_PIPE` | `false` | enables pipes in commands |
| `NETMIKO_MCP_SSH_CONFIG_FILE` | *(none)* | OpenSSH `ssh_config`. **Required for jumphosts** — Netmiko does not read `~/.ssh/config` on its own |
| `NETMIKO_MCP_MAX_WORKERS` | `10` | concurrent connections in group commands |
| `NETMIKO_MCP_SAVE_OUTPUT_DIR` | `~/.netmiko_mcp_tmp` outside Niko | buffer for large outputs |
| `NETMIKO_MCP_SAVE_THRESHOLD` | `1000` | line count above which output is saved instead of returned inline |
| `NETMIKO_MCP_AUDIT_LOG_FILE` | *(see the parent README)* | audit trail (JSON, fail-closed). Ask the agent to read it with `netmiko.query_audit_trail` |
| `NETMIKO_MCP_CONFIG` | `~/.netmiko-mcp.yml` | path to a YAML config file holding these same settings |
| `LOG_FILE` / `LOG_LEVEL` | `Niko.log` / `INFO` | operational log: stderr always, plus this rotating file (5 MB × 3, `0600`). `LOG_LEVEL` is stated at its default so the knob is where you look for it — set it to `DEBUG` and the device output lands in the log |

Credentials are *not* set here. `NETMIKO_USERNAME`, `NETMIKO_PASSWORD`,
`NETMIKO_SECRET` and the `FEDELE_*` variables are read from
`<project-root>/.env`, so that they never end up in a committed JSON file.
Precedence: what is in the `env` block wins over the `.env`, silently — define
each variable in exactly one place.

Every other variable is documented in the parent repository's README.

## Checking that it works

```bash
claude mcp list          # netmiko: ✓ connected
```

Inside the session, `/mcp` lists the tools and `/skills` confirms the skill was
loaded. Ask which policy is in force and `netmiko.get_command_policy` names the
file it is reading — or reports `"fallback"`, which means it never found the
file and is running on the 16 built-in commands.

---

*Author: Ed Scrimaglia <edgardo.scrimaglia@gmail.com> — last updated: 2026-08-18.*
