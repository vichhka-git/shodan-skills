# Configuration

## Storing a key

```bash
python3 scripts/shodan_api.py config set
```

This prompts for the key without echoing it, verifies it against `/api-info`, then writes it
to `~/.config/shodan-skills/config.json` with mode `0600` inside a directory with mode `0700`.
The file is opened with those permissions before anything is written, so the key is never
briefly readable by other users.

To pipe a key in from a secret manager or a script:

```bash
printf '%s' "$KEY" | python3 scripts/shodan_api.py config set --stdin
```

`--no-verify` skips the `/api-info` check for offline setup.

**The key never goes in argv.** `config set` has no `--key` option, by design: an argument
lands in shell history, in `ps` output, and in any shell transcript. The prompt and stdin
avoid all three.

## Where the key comes from

The first source that has one wins:

| Order | Source | Use it for |
|---|---|---|
| 1 | `SHODAN_API_KEY` environment variable | CI, containers, one-off overrides |
| 2 | `~/.config/shodan-skills/config.json` | Normal local use |
| 3 | `~/.shodan/api_key` | A key the official Shodan CLI already stored |

`config show` reports every source it found, which one is active, and the key masked to its
first and last four characters. `$XDG_CONFIG_HOME` moves the config directory;
`$SHODAN_SKILLS_CONFIG` points at a specific file, which is useful for keeping a test key
separate from a working one.

## Permissions

If the config file is readable by group or other, every command prints a warning to stderr
and keeps working. Fix it with:

```bash
python3 scripts/shodan_api.py config repair
```

`config remove` deletes the stored key and leaves any other settings in the file.

## Checking a key

```bash
python3 scripts/shodan_api.py config test
```

Reports the active source, the masked key, the plan name, remaining query and scan credits,
and the monitored-IP limit. A bad key returns `auth` with exit code 4; no key at all returns
`config` with exit code 3.

## CI and containers

Pass the key as `SHODAN_API_KEY` from the runner's secret store. Do not write a config file
into an image layer, and do not commit one: the repository ignores `config.json` and `.env`
for that reason. In a shared or multi-tenant shell the environment variable is visible to
anything running as the same user, so prefer the config file on a workstation and the
environment variable only where the process is isolated.

## What is redacted

The client registers the resolved key as a secret and strips it from everything it prints,
including response bodies. Shodan's `scan list` echoes an `api_key` field for each scan, and
it arrives as `<redacted>`. Values passed with `--arg` are registered too, so a webhook URL
or provider token does not reappear in output. Error messages and `--dry-run` plans also drop
any `key=` query parameter.

Response data is otherwise left intact. A scanned host's banner can legitimately contain the
text `key=`, and the client does not rewrite that.
