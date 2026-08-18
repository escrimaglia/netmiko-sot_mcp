---
name: netmiko
description: >-
  Load this skill whenever the user asks about network devices — routers,
  switches, firewalls — or uses netmiko MCP tools. Covers running show
  commands over SSH, device inventory, device groups, per-platform CLI syntax,
  and why a command was refused. Also load for netmiko MCP identity, version or
  capability questions.
  Trigger phrases: "router", "switch", "firewall", "equipo de red", "show
  version", "show run", "display version", "estado del router", "listar
  dispositivos", "inventario de red", "grupo de equipos", "correr un comando en",
  "conectate al router", "SSH", "netmiko", "device inventory", "run a show
  command", "check the switch".
---

> **Naming note (Claude Code).** This document refers to the tools as
> `netmiko.<tool>`, which is how the server registers them. Claude Code exposes
> them prefixed with the server name declared in `.mcp.json`: `mcp__netmiko__…`.
> Run `/mcp` in the session to see the exact names.

# Netmiko — Read-Only Network Device Access

Netmiko MCP runs **show commands** over SSH against routers, switches and
firewalls. Niko reaches network devices **only** through `netmiko.*` tools.

> **Scope:** runtime behaviour — command routing, per-platform syntax, why a
> command was refused, large-output pagination. General agent governance →
> `context/niko_context.md`. Source-of-truth data (sites, IPAM, circuits) →
> the `fedele` skill.

---

## When to Load This Skill

Load **before** any operation that touches a network device:

- Running any command against a router, switch or firewall.
- Asking what devices or groups exist.
- Interpreting a refused command or a connection failure.
- Retrieving output that was saved to disk because it was too large.

Load it **also** when nothing is going to be executed but the question is about
this server: *"what is netmiko?"*, *"what can you do with the network?"*, *"which
commands can I run?"*, *"what version is it?"*. These touch no device, so the rule
above does not cover them — and answering them from memory instead of from this
skill is how a user ends up with a description of some other deployment.

### "What is netmiko?"

Answer about **this MCP server and what it can do here**, not about the Python
library of the same name. It is read-only access to network devices over SSH:
show commands only, no configuration tool, every command checked against the
operator's allow/deny list before any connection is opened, every attempt
audited. Devices are reached by inventory name, never by address.

Make it concrete with `netmiko.get_metadata` — version, inventory backend and the
platforms actually present — and with `netmiko.get_command_policy` if they ask
what can be run. "It runs show commands on the 7 devices in this inventory, all
`cisco_ios`" is an answer; a definition of the library is not.

Netmiko *is* also a Python library, and this server is built on it. Say that only
if the user is clearly asking about the library itself, and keep it to a sentence.

Do **not** load this skill for questions about the *documented* state of the
network (what site a device is in, which IP range is assigned) — that is Fedele,
and it answers without touching any equipment.

---

## Core Rule: Call `netmiko.get_metadata` First

Call it before any other `netmiko.*` tool. It returns three things you cannot
guess:

1. **`inventory.backend`** — whether devices are resolved from the live source of
   truth or from a local file. If it is `yaml`, check `age_days`: operating from
   a stale local inventory can send a command to the wrong box.
2. **`device_types_in_inventory`** — the platforms actually present. This decides
   the command syntax you must use (see below).
3. **`command_syntax_warning`** — read it. It is not boilerplate.
4. **`command_policy`** — `file` when the operator's allow/deny list is in force,
   `fallback` when no policy file exists and only a handful of built-in read-only
   commands will run (see below).

If it reports a `warning`, surface it to the user before running anything.

---

## Your Behaviour Depends on the Active Configuration

The server can be configured three ways, and `netmiko.get_metadata` tells you
which one is running. Two fields matter: `inventory.backend` and
`credential_source`. They are independent — the inventory can come from the
source of truth while credentials come from the agent's environment.

### Inventory `fedele` — live source of truth

Addresses are resolved per request, so they are current. Two consequences:

- The device list is a **subset** and says so (see below).
- If the source of truth is unreachable you get `Fedele Error`. That means **you
  do not know where the device is** — not that the device is down. Never report
  it as an unreachable router.

### Inventory `yaml` — local file, possibly stale

`get_metadata` reports `age_days` and adds a `warning` past 30 days.

- If there is a `warning`, **say it before running anything**, once, naming the
  age: *"the local inventory has not been updated in 214 days; addresses may be
  out of date"*. Then proceed if the user wants to.
- **Do not refuse to operate.** The operator chose this mode, usually because the
  source of truth is down and this is the fallback that keeps things working.
- **Never "correct" an address you believe is wrong.** You have no better source,
  and a command sent to a guessed address is the failure this whole design exists
  to prevent.

### When the source of truth is down

There is a lever — switching `NETMIKO_MCP_INVENTORY_TYPE` to `yaml` — but:

- It is an **operator decision**, not a fix you can apply or should push. It needs
  a configuration change and a server restart.
- The local file may be old. Switching trades "no inventory" for "possibly stale
  inventory", and only the operator knows if that trade is acceptable right now.
- Mention it as an available option, once, and move on.

**Do not retry in a loop.** After a transport failure the server short-circuits
requests for 30 seconds; retrying inside that window returns the same error
without ever reaching the network. Wait or report.

### Credential source — where to send the user when auth fails

You never see credentials in either mode; they are resolved server-side and no
tool returns them. It matters only for **diagnosing a `Credential Error`**, and
it changes where the fix is:

| `credential_source` | Where the credential lives | What to tell the user |
|---|---|---|
| `env` | The agent's environment | Check `NETMIKO_USERNAME` / `NETMIKO_PASSWORD` / `NETMIKO_SECRET` in the agent configuration |
| `fedele` | Credentials section of the source of truth | The device has no usable credential associated in the source of truth |

Sending someone to edit the agent's environment when the credential actually
lives in the source of truth — or the reverse — wastes real time. Read
`credential_source` before advising.

A `Credential Error` is never something to retry: nothing changes between
attempts, and repeated failed logins against TACACS+ can lock the service account.

---

## The Rule That Breaks Most Often: Syntax Is Per-Platform

Netmiko drives **177 base device types (416 with variants) from 102 vendors**.
Their CLIs are **not interchangeable**. The same intent is a different command:

| Intent | Cisco IOS / XR, Arista, Extreme | Huawei VRP, HPE Comware | Juniper Junos | MikroTik RouterOS |
|---|---|---|---|---|
| software version | `show version` | `display version` | `show version` | `/system resource print` |
| interface summary | `show ip interface brief` | `display ip interface brief` | `show interfaces terse` | `/interface print` |
| routing table | `show ip route` | `display ip routing-table` | `show route` | `/ip route print` |
| running config | `show running-config` | `display current-configuration` | `show configuration` | `/export` |
| neighbours | `show lldp neighbors` | `display lldp neighbor` | `show lldp neighbors` | `/ip neighbor print` |

**Before composing a command:**

1. Get the device's `device_type` from `netmiko.list_devices`.
2. Use that platform's syntax.

**Never** translate a command from one family to another by analogy, and
**never** probe variants to see which one is accepted. Every attempt is audited,
and a wrong guess against an unfamiliar platform produces an error message from
the device that is easy to misread as the device being broken.

If you do not know the correct syntax for a platform, say so and ask. That is a
better answer than a command that fails in an ambiguous way.

---

## Devices Are Named, Never Addressed

Every tool takes a **device name from the inventory**. There is no parameter for
an IP address or a hostname, by design: the name → address mapping is resolved
server-side, so the inventory acts as the list of machines the agent is allowed
to reach.

- Get exact names with `netmiko.list_devices`.
- Never invent a name, never "correct" one, never pass an address.
- If a name does not resolve, report that — do not try variations.

---

## Turning What the User Said Into a Device Name

Users rarely say a device name. They say an address, a tenant, a site, a role, a
customer, half a name. Every `netmiko.*` tool needs the name, so something has to
resolve the gap — and **which path is available depends on the active inventory
backend**, not on what would be convenient.

Read `inventory.backend` from `netmiko.get_metadata` first.

### `inventory.backend: fedele` — resolve the attribute against the source of truth

The source of truth can be searched by any attribute it stores. Use the `fedele`
skill's tools for the lookup, then bring **only the device name** back to netmiko:

1. Search the source of truth by whatever the user gave you — tenant, management
   address, site, role, partial name.
2. Take the `name` field from each matching device.
3. Call `netmiko.send_show_command(device_name=<that name>)`.

**Bring back the name, never the address.** The lookup result contains a
management IP, and there is no netmiko parameter that accepts one — see *Devices
Are Named, Never Addressed*. The name→address mapping is resolved server-side on
purpose, so a name is the only thing worth carrying across.

Two results that are not a device name:

- **Several matches** → ask which one. Do not pick the first, and do not run the
  command on all of them unless the user asked for that.
- **No match** → say the attribute matched nothing in the source of truth. Do not
  fall back to guessing a name, and do not retry the same search against netmiko.

### `inventory.backend: yaml` — the listing is the whole universe

In this mode the server **never contacts the source of truth**. There is nothing
to resolve externally, and going to the `fedele` tools for an address would
produce one that netmiko cannot accept and has no way to verify.

- Match what the user described against `netmiko.list_devices` and
  `netmiko.list_groups`. Those two listings are the complete world.
- If it is not in the listing, it does not exist for netmiko. Say that. The
  operator chose a local inventory; a device missing from it is either genuinely
  out of scope or the file is stale — and `get_metadata` reports the age.

### Either way, the operator may have narrowed the scope

`get_metadata` reports `inventory.scope_filter`. When it is set, the inventory is
deliberately restricted to a slice of the estate, and a device outside it returns:

```
Inventory Error: El dispositivo 'X' no existe en Fedele, o queda fuera del
alcance configurado ({'tag': '...'}).
```

That message cannot distinguish the two cases, so do not resolve it for the user.
Report both possibilities and name the active filter — it is the operator's
setting and the operator is the one who can widen it.

---

## The Inventory Is a Subset, and It Says So

A source of truth catalogues more than SSH-manageable network gear: cameras,
access control, load balancers, chassis controllers. Those are **excluded**.

When `netmiko.list_devices` returns `excluded_count` and `excluded_reasons`, the
listing is **not** the full estate. Report it that way:

> "24 manageable devices. 37 more exist in the inventory but are not reachable
> over SSH: 19 have no management IP and 18 run platforms Netmiko does not
> drive."

Never present a filtered listing as "these are all the devices".

If the user asks specifically about an excluded device, the error states the
reason — a missing management IP, or a platform that is not a Netmiko device
type. Relay that reason instead of "not found".

---

## Tool Map

| Tool | Use it for |
|---|---|
| `netmiko.get_metadata` | Identity, active inventory backend, platforms present. **First.** |
| `netmiko.get_command_policy` | Which commands this server accepts, and whether the policy is the operator's file or the built-in fallback. **After a refusal, before any retry.** |
| `netmiko.health_check` | Is the MCP server itself alive. Touches no device. |
| `netmiko.list_groups` | What groups exist. Call before assuming a group name. |
| `netmiko.list_devices` | Exact device names and their `device_type`. |
| `netmiko.send_show_command` | One command, **one** device. |
| `netmiko.send_show_command_to_group` | The same command across a group, concurrently. |
| `netmiko.list_device_outputs` | Output already saved to disk. |
| `netmiko.read_device_output` | Read a saved output, paginated. |

### One device or a group?

- The user names a device → `send_show_command`.
- The user names a group, or says "on all of them" → `send_show_command_to_group`.
- The user names several unrelated devices → one `send_show_command` each.

### Groups can mix platforms

`send_show_command_to_group` sends the **same string** to every member. A group
holding both Cisco IOS and Huawei VRP devices will fail on half of them whatever
you send.

Check `device_type` across the group first. If it is heterogeneous, issue one
`send_show_command` per platform instead of forcing one string onto all of them —
and tell the user why you split it.

---

## Refused Commands Are Policy, Not Failures

Every command is checked against an operator-defined allow/deny list **before any
connection is opened**. A refusal means the operator did not authorise that
command.

```
Security Error: Command 'show tech-support' is not permitted.
```

**What to do:** call `netmiko.get_command_policy`. It returns the allow and deny
lists actually in force, so you can offer a command that will pass instead of
guessing at one. Then tell the user which command was refused, and either propose
the allowed alternative or say plainly that the policy does not cover what they
asked for.

**What never to do:**

- Do not retry with an abbreviation. The allow list matches exactly or by glob and
  does **not** cover abbreviations, while the deny list **does**. `sh ver` is not
  permitted by `show version`, and it *is* blocked by a deny on `show version`.
  Send full, un-abbreviated commands.
- Do not try synonyms or variants to find one that passes. That is probing an
  access control, every attempt is audited, and it will read as exactly that.
- Do not use `send_show_command_to_group` to get around a refusal. Validation
  happens once, before any device is contacted.
- Do not tell the user the tool is broken. It did what it is for.

There is **no configuration tool**. This server cannot change device state. If
asked to configure something, say that plainly and offer to show the current
state instead.

### `command_policy: fallback` — nobody wrote a policy yet

When `netmiko.get_metadata` (or `netmiko.health_check`) reports
`command_policy: "fallback"`, no allow/deny file exists on this deployment. The
server is running on a built-in read-only list — roughly "what version is this,
what interfaces does it have, how does it route, who is it connected to" — across
Cisco, Junos and Huawei syntax. Everything else is refused.

**What to do:**

- Say so **before** running anything, quoting the `warning` field. The refusals
  that follow are not device problems and not your mistakes, and the user has no
  way to know that unless you tell them.
- Name the fix once: the operator has to create the command policy file the
  warning points at — `config/netmiko/commands.yml` under Niko, `.yaml` works
  too — and restart the MCP server. It is read once, at startup.
- Keep working. The fallback commands are real commands; run the ones that fit
  the question and report what you could not answer.

**What never to do:** do not go hunting for which commands happen to pass. In
this mode the deny list is empty and the allow list is exact — every probe is a
refusal, and every refusal is audited as one.

---

## Large Output

Output above the configured line threshold is **not returned inline** — it is
saved to disk so it does not consume the whole context window:

```
Output too large to return inline (4,812 lines, exceeds save_threshold of 1,000).
Automatically saved as 'show_ip_route_20260813_214447.txt'.
Use netmiko.read_device_output to retrieve it.
```

Then:

1. `netmiko.list_device_outputs(device_or_group=<device>)` → filenames, newest first.
2. `netmiko.read_device_output(device_name=…, filename=…, offset=0, limit=500)`.

The response header states the range and the total:

```
Lines 1-500 of 4812. Call netmiko.read_device_output with offset=500 to continue.
```

**Never state a total based on a page you have not finished reading.** If the
user asks "how many BGP routes", either page through to the end or say you read
the first N lines of M.

Use `save_output=True` deliberately when you know you will refer back to the same
output several times.

---

## Structured Output (`use_textfsm`)

`use_textfsm=True` parses the output into JSON via ntc-templates. Use it when you
need to **compute** over the result — count interfaces, filter by state, compare
across devices.

It **falls back to raw text** when no template exists for that command and
platform. That is normal, not an error. If you get text back after asking for
parsing, work with the text; do not retry.

For output the user will simply read, plain text is usually better.

---

## Error Contract

Every tool returns JSON with `success`. On failure, `error` carries a prefix that
tells you where the problem is — and they need different answers:

| Prefix | Meaning | What to do |
|---|---|---|
| `Security Error` | Command not allowed by policy | Report the refusal. Do not retry. |
| `Inventory Error` | Device or group does not resolve | List devices/groups. Do not guess names. |
| `Credential Error` | No usable credential for that device | Operator action. Do not retry. |
| `Fedele Error` | The source of truth is unreachable | Say the **inventory source** failed — you know nothing about the device. Do not conclude the device is down. |
| `Connection Error` | Reached the device layer and failed | Authentication, timeout or SSH error. This *is* about the device. |
| `Execution Error` | Unexpected fault | Report it; it is a bug worth surfacing. |

The distinction between `Fedele Error` and `Connection Error` matters: the first
means you could not find out where the device is, the second means you got there
and it did not answer. Reporting the first as "the router is down" is wrong.

### Partial group results

`send_show_command_to_group` returns a result **per device**. Some may succeed
while others fail. Report it as partial, listing which devices failed and why.
Never summarise a partial run as if every device answered.

---

## Anti-patterns

1. Composing a command without checking the device's `device_type` first, then
   reporting the platform's syntax error as a device fault.
2. Retrying a refused command with an abbreviation or a synonym.
3. Presenting a filtered device listing as the complete estate.
4. Passing an IP address where a device name is expected.
5. Reporting a total from a paginated output you did not finish reading.
6. Sending one command to a heterogeneous group and reporting the failures as
   device problems.
7. Reading `Fedele Error` as "the device is down".
8. Offering to change a device's configuration. There is no tool for it.
9. Operating from a stale local inventory without saying so, or "correcting" an
   address you believe is wrong.
10. Telling the user to check the agent's environment when `credential_source` is
    `fedele` — the credential lives in the source of truth, not in a variable.
11. Carrying a management address back from a source-of-truth lookup instead of
    the device name, or querying the source of truth at all when
    `inventory.backend` is `yaml`.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every tool returns the same `Startup Error` | Server misconfiguration. Relay the message verbatim — it names what is missing. |
| `existe en Fedele pero no es gestionable` | The device has no management IP, or its platform is not a Netmiko device type. |
| `queda fuera del alcance configurado` | An `inventory.scope_filter` is set. The device may exist and simply be outside it — the message cannot tell. Name the filter; only the operator can widen it. |
| `no tiene dispositivos asignados` | The group exists but is empty. Different from a wrong name. |
| `ninguno es gestionable por Netmiko` | The group has members, but none reachable over SSH. |
| `Fedele no disponible … reintentar en Ns` | The source of truth is down; the circuit breaker is open. It closes on its own — do not retry inside the window. |
| `Credential Error` with `credential_source: env` | Missing or wrong `NETMIKO_*` variables in the agent environment. |
| `Credential Error` with `credential_source: fedele` | The device has no usable credential in the source of truth, or the decryption key is missing. |
| `inventory.warning` about age | Running from a stale local inventory. Surface it; do not silently trust the addresses. |
| Almost every command refused, and `command_policy: fallback` | No policy file on this deployment; only the built-in read-only commands run. Quote the `warning`, name the file the operator has to create, and do not probe for what passes. |
| Structured parsing returned plain text | No ntc-templates template for that command and platform. Expected. |
