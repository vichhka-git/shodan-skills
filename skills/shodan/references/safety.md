# Safety

Read this before any operation that spends credits, changes state, scans, monitors, or
downloads.

## Credits

Four operations spend credits. Nothing else does.

| Operation | Cost |
|---|---|
| `search hosts` | 1 query credit per page |
| `dns domain` | 1 query credit |
| `scan submit` | 1 scan credit per IP |
| `scan internet` | Plan-dependent, enterprise only |

Credits reset monthly and do not roll over. `account api-info` reports the balance;
`account profile` does not, whatever its `credits` field suggests.

Two habits save most of the waste:

- Use `search count` instead of `search hosts` when the user wants a number or a facet
  breakdown. `count` is free and returns the same facets.
- Check `search count` first when paginating. Each page of `search hosts` costs a credit, so
  knowing the total avoids walking pages that do not exist.

When credits run out, Shodan returns HTTP 402 and the client reports `credits` with exit
code 6. Retrying does not help, and neither does splitting the query. Report the balance.

## Operations that change state

`alert create`, `alert edit`, `alert trigger-enable`, `alert trigger-ignore`,
`alert trigger-unignore`, `alert notifier-add`, `notifier create`, `notifier edit`,
`scan submit`, `scan internet`, `org member-add`, and the six confirm-gated operations below
all change something on the account. An explicit user request authorizes the matching
operation, and only that one.

## Operations that need `--confirm`

| Operation | What is lost |
|---|---|
| `alert delete` | The alert and its trigger configuration |
| `alert trigger-disable` | A trigger's configuration on that alert |
| `alert notifier-remove` | The link between an alert and a notifier |
| `notifier delete` | The notifier, and its link to every alert using it |
| `org member-remove` | The member's organization access |
| `scan internet` | Nothing, but it crawls the whole internet for a port |

These refuse to run without the flag. Pass it when the user has asked for that specific
action. Do not pass it to get past a refusal the user did not ask you to override, and do not
add `--confirm` to a batch of operations where only one of them needed it.

`--dry-run` prints the exact request without sending it, and works on every operation. Use it
to show the user what a destructive call would do before running it.

## Scanning

`scan submit` asks Shodan to scan hosts on the user's behalf. Scan only what the user named.
Do not expand a single address into its subnet, do not add neighbouring ranges, and do not
scan infrastructure the user has not shown authorization for. `scan submit` accepts CIDR
ranges, which makes accidental widening easy: `8.8.8.0/24` is 256 hosts and 256 credits.

`scan internet` is a different thing entirely. It crawls the entire public internet for one
port and protocol, takes a long time, and is enterprise-only. It needs `--confirm`.

## Streaming

Streaming feeds never end on their own. Always bound a run:

```bash
python3 scripts/shodan_api.py stream alerts --duration 30 --limit 50
```

`--limit` stops after a number of records, `--duration` after a number of seconds, and
`--idle-timeout` after a gap with no data at all. With none of them the command runs until
the feed closes or the process is killed. The final line on stderr reports the record count
and why it stopped: `limit-reached`, `duration-reached`, `idle-timeout`, `feed-closed`, or
`interrupted`.

A quiet feed blocks inside a socket read, so `--duration` is what sets the read timeout. An
account with no alerts configured produces no records at all, which is not an error.

## Targets

Every address, hostname, ASN, country code, port, CVE identifier, and path segment is
validated locally before a request is built. A rejected argument returns `usage` with exit
code 2 and sends nothing. This is also what prevents a crafted identifier from escaping its
place in the URL path.

Keep the target set to what the user asked for. Shodan's data covers third-party hosts, and
an exposure report on infrastructure the user does not own should say whose it is.

## Entitlements

Twelve operations need more than a standard plan and return `access` with HTTP 403 otherwise:
`scan internet`, `data list`, `data files`, all three `org` operations, and the six
enterprise `stream` feeds. A 403 here is a plan boundary, not a bug and not a key problem.
Name the plan requirement and stop; do not retry and do not try a different endpoint to get
the same data.
