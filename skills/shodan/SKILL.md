---
name: shodan
description: Query the Shodan APIs for host intelligence, exposure research, search and facets, DNS, on-demand scans, network alerts and notifiers, bulk datasets, organizations, account credits, live banner streams, historical trends, and CVE/CPE vulnerability lookups. Use for any Shodan lookup, internet-exposure question, attack-surface review, monitoring setup, credit or plan check, or CVE and KEV research. Also use to store a Shodan API key securely.
---

# Shodan

A zero-dependency Python client for the documented Shodan APIs. Every call goes through
`scripts/shodan_api.py`, which prints a stable JSON envelope on stdout and returns a
documented exit code.

## Before the first call

Run `python3 scripts/shodan_api.py config test`. It resolves the API key and reports the
plan and remaining credits. If it reports no key, read [configuration](references/configuration.md)
and set one up. Never ask the user to paste a key into a command, a prompt, a source file,
or a chat message: `config set` reads it from a hidden prompt or stdin so it never reaches
argv, shell history, or the process list.

Paths here are relative to this skill folder. Use the folder's absolute path if the working
directory is elsewhere.

## Running an operation

```bash
python3 scripts/shodan_api.py GROUP ACTION [arguments]
```

`python3 scripts/shodan_api.py operations` prints all 61 operations as JSON with method, path,
access class, and credit cost. `GROUP ACTION --help` gives the exact arguments for one.
[operations](references/operations.md) is the same inventory in readable form.

Do this in order:

1. Pick the operation from [operations](references/operations.md). Match what the user asked
   for, and do not widen the target set or add operations they did not request.
2. Check the credit and access columns. Read [safety](references/safety.md) before anything
   that spends credits, changes state, scans, monitors, or downloads.
3. Run it. An explicit user request is the authorization. Do not ask for a second
   confirmation, except for the destructive operations listed below, which need `--confirm`.
4. Parse stdout as JSON. On `"ok": false` read `error.type` and act on it rather than retrying
   blindly.

## Reading the result

Success:

```json
{"ok": true, "command": "host info", "data": {...}, "notes": ["consumes query credits"]}
```

Failure, with a nonzero exit code:

```json
{"ok": false, "command": "search hosts", "error": {"type": "credits", "message": "...", "status": 402}}
```

Streaming operations write one JSON object per line to stdout and a final summary to stderr.
Everything else writes one envelope.

| `error.type` | Exit | What it means | What to do |
|---|---|---|---|
| `usage` | 2 | An argument was rejected locally | Fix the argument; no request was sent |
| `config` | 3 | No key, or an unreadable config file | Run `config set` |
| `auth` | 4 | The key was rejected | Check the key with `config test` |
| `access` | 5 | The plan lacks this entitlement | Tell the user which plan it needs; do not retry |
| `credits` | 6 | Out of query or scan credits | Check `account api-info`; do not retry |
| `api` | 7 | Shodan returned an error | Read the message; 503 means the service is down upstream |
| `network` | 8 | Could not reach Shodan | Retry once, then report it |

## Rules that matter

- **Credit balances come from `account api-info`**, never from `account profile`. The profile
  response has a generic `credits` field that is not the query or scan balance.
- **`search count` is free, `search hosts` costs one query credit per page.** Use `count` when
  the user wants a number or a facet breakdown, and `hosts` only when they need the records.
- **Six operations require `--confirm`**: `alert delete`, `alert trigger-disable`,
  `alert notifier-remove`, `notifier delete`, `org member-remove`, `scan internet`. Pass it
  when the user has clearly asked for that action. Do not pass it to work around a refusal
  the user did not ask you to override.
- **`--dry-run` prints the request without sending it.** Use it when the user wants to preview,
  and to show what a destructive call would do.
- **Never print the API key.** The client masks it everywhere, including inside responses:
  Shodan's own `scan list` echoes an `api_key` field and it arrives as `<redacted>`. Do not
  undo that by reading the config file directly.
- **Report what actually happened.** If an operation failed or was skipped for lack of
  entitlement, say so rather than describing what it would have returned.

## Choosing the reference

- [operations](references/operations.md): all 61 operations with method, path, credits, access.
- [configuration](references/configuration.md): key storage, precedence, file permissions, CI.
- [search syntax](references/search-syntax.md): filters, facets, pagination, query building.
- [safety](references/safety.md): credits, mutations, scanning, streaming, and target scoping.

## Entitlements

The `standard` operations work on any paid plan. Twelve operations need a higher entitlement
and return `access` with HTTP 403 without it: `scan internet`, both `data` operations, all
three `org` operations, and six of the eight `stream` operations. `stream alerts` and
`stream alert` work on a standard plan. The `cve` group queries Shodan's CVEDB service and
needs no API key at all.
