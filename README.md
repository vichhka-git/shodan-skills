# shodan-skills

An agent skill for the Shodan APIs. Install it into your coding agent and ask for internet
exposure data in plain language: the agent picks the right endpoint, respects your credit
balance, and reads back structured results.

61 operations across Shodan's REST, Streaming, Trends, and CVEDB services. No runtime
dependencies: one Python 3 file using only the standard library.

Not affiliated with, endorsed by, or sponsored by Shodan.

## Install

```bash
npx skills add vichhka-git/shodan-skills -g
```

`-g` installs at user level, so the skill is available in every project. For Claude Code that
lands in `~/.claude/skills/shodan`; other agents use their own directory, selectable with
`-a claude-code` (or `codex`, `cursor`, `gemini`). Drop `-g` to install into the current
project instead, at `./.claude/skills/shodan`.

Store your API key from your [Shodan account page](https://account.shodan.io):

```bash
python3 ~/.claude/skills/shodan/scripts/shodan_api.py config set
```

The prompt does not echo. The key is verified against Shodan, then written to
`~/.config/shodan-skills/config.json` with mode `0600`. Check it with `config test`.

Requires Python 3.9 or newer, which macOS and every current Linux ship.

## Usage

The skill is driven by your agent, but the script is a normal CLI:

```bash
cd ~/.claude/skills/shodan

# Free: everything known about one host
python3 scripts/shodan_api.py host info 8.8.8.8

# Free: how many hosts match, broken down by country
python3 scripts/shodan_api.py search count --query 'vuln:CVE-2014-0160' --facets country:10

# 1 query credit: the actual records
python3 scripts/shodan_api.py search hosts --query 'product:nginx country:DE'

# No API key needed
python3 scripts/shodan_api.py cve info CVE-2014-0160

# Show the request without sending it
python3 scripts/shodan_api.py scan submit --ips 8.8.8.8 --dry-run
```

Every command prints one JSON envelope and returns a documented exit code (`2` usage,
`3` config, `4` auth, `5` access, `6` credits, `7` api, `8` network):

```json
{"ok": true, "command": "host info", "data": {"ip_str": "8.8.8.8", "ports": [53, 443]}}
```

### Operations

| Group | Count | What it answers |
|---|---|---|
| `host` | 1 | Everything Shodan holds for one IP |
| `search` | 5 | Queries, counts, facets, filters, query parsing |
| `cve` | 5 | CVE, CPE, KEV, EUVD, and GHSA lookups, no key needed |
| `dns` | 3 | Forward and reverse resolution, domain records |
| `scan` | 6 | On-demand scans, crawled ports and protocols |
| `alert` | 12 | Network alerts, triggers, notifier bindings |
| `notifier` | 6 | Email, Slack, Telegram, webhook, PagerDuty, Jira targets |
| `stream` | 8 | Live banner feeds by ASN, country, port, vulnerability, alert |
| `trends` | 3 | Monthly historical counts back to 2017 |
| `account` | 2 | Plan, query credits, scan credits, monitored-IP limits |
| `query` | 3 | The community saved-query directory |
| `tools`, `data`, `org` | 7 | Diagnostics, bulk datasets, organization members |

Run `python3 scripts/shodan_api.py operations` for the full inventory as JSON, with method,
path, credit cost, and access class per operation. `GROUP ACTION --help` documents one.

### Key handling

`config set` reads the key from a hidden prompt or stdin. There is no `--key` flag, because an
argument would land in shell history and in `ps` output. The config file is created with mode
`0600` inside a `0700` directory before any bytes are written. Resolution order is
`SHODAN_API_KEY`, then the config file, then `~/.shodan/api_key` from the official Shodan CLI.

The key is stripped from everything printed, including response bodies: Shodan's `scan list`
echoes an `api_key` field, and it comes back `<redacted>`.

### Guardrails

Four operations spend credits, and the skill prefers the free `search count` over
`search hosts` when a number will do. Six destructive operations refuse to run without
`--confirm`: deleting an alert or notifier, disabling a trigger, unbinding a notifier,
removing an organization member, and launching an internet-wide scan. `--dry-run` works on
all 61. Targets are validated locally before a request is built, and streaming runs are
bounded by `--limit`, `--duration`, and an idle timeout.

## License

MIT. See [LICENSE](LICENSE).
