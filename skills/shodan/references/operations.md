# Operations

All 61 operations, grouped. Run `python3 scripts/shodan_api.py GROUP ACTION --help`
for the exact arguments of any one, or `operations` for this table as JSON.

Columns: **Credits** is what the call spends. **Access** is `standard` unless the plan needs
a higher entitlement. A command marked **confirm** refuses to run without `--confirm`.

## Account and plan

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `account api-info` | `GET /api-info` | none | standard | Plan, query credits, scan credits, and monitored-IP limits |
| `account profile` | `GET /account/profile` | none | standard | Membership and profile metadata, not credit balances |

## Host intelligence

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `host info` | `GET /shodan/host/{ip}` | none | standard | All banners Shodan holds for one IP |

## Search

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `search hosts` | `GET /shodan/host/search` | **query** | standard | Search the host index; consumes 1 query credit per page |
| `search count` | `GET /shodan/host/count` | none | standard | Result count and facets without consuming query credits |
| `search facets` | `GET /shodan/host/search/facets` | none | standard | Facet names available to search queries |
| `search filters` | `GET /shodan/host/search/filters` | none | standard | Search filter names available to queries |
| `search tokens` | `GET /shodan/host/search/tokens` | none | standard | Break a query into its parsed filters and errors |

## Saved queries

Shodan's saved-query endpoints have been returning HTTP 503 upstream. The client surfaces that as `api` with status 503.

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `query list` | `GET /shodan/query` | none | standard | Saved search queries from the community directory |
| `query search` | `GET /shodan/query/search` | none | standard | Search the saved-query directory |
| `query tags` | `GET /shodan/query/tags` | none | standard | Most popular tags in the saved-query directory |

## DNS

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `dns resolve` | `GET /dns/resolve` | none | standard | Resolve hostnames to IP addresses |
| `dns reverse` | `GET /dns/reverse` | none | standard | Reverse-resolve IP addresses to hostnames |
| `dns domain` | `GET /dns/domain/{domain}` | **query** | standard | Subdomains and DNS records for a domain; consumes 1 query credit |

## Tools

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `tools myip` | `GET /tools/myip` | none | standard | The external IP address Shodan sees for this caller |
| `tools httpheaders` | `GET /tools/httpheaders` | none | standard | HTTP headers this caller sends |

## Scanning

`scan submit` spends scan credits. `scan internet` crawls the whole internet for one port and needs an enterprise entitlement.

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `scan ports` | `GET /shodan/ports` | none | standard | Ports Shodan crawls |
| `scan protocols` | `GET /shodan/protocols` | none | standard | Protocols available to on-demand scans |
| `scan list` | `GET /shodan/scans` | none | standard | Scans submitted by this account |
| `scan status` | `GET /shodan/scan/{id}` | none | standard | Progress of one submitted scan |
| `scan submit` | `POST /shodan/scan` | **scan** | standard | Request an on-demand scan; consumes scan credits |
| `scan internet` **confirm** | `POST /shodan/scan/internet` | **unknown** | **enterprise** | Crawl the whole internet for one port and protocol |

## Network alerts

Alert bodies are sent as JSON. `--ips` accepts addresses or CIDR ranges and is written into the `filters.ip` list Shodan expects.

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `alert list` | `GET /shodan/alert/info` | none | standard | Network alerts owned by this account |
| `alert info` | `GET /shodan/alert/{id}/info` | none | standard | One network alert and its triggers |
| `alert triggers` | `GET /shodan/alert/triggers` | none | standard | Trigger types that alerts can enable |
| `alert create` | `POST /shodan/alert` | none | standard | Create a network alert for a set of IPs |
| `alert edit` | `POST /shodan/alert/{id}` | none | standard | Replace the IP list monitored by an alert |
| `alert delete` **confirm** | `DELETE /shodan/alert/{id}` | none | standard | Delete a network alert |
| `alert trigger-enable` | `PUT /shodan/alert/{id}/trigger/{trigger}` | none | standard | Enable a trigger on an alert |
| `alert trigger-disable` **confirm** | `DELETE /shodan/alert/{id}/trigger/{trigger}` | none | standard | Disable a trigger on an alert |
| `alert trigger-ignore` | `PUT /shodan/alert/{id}/trigger/{trigger}/ignore/{service}` | none | standard | Stop one service from firing a trigger |
| `alert trigger-unignore` | `DELETE /shodan/alert/{id}/trigger/{trigger}/ignore/{service}` | none | standard | Let an ignored service fire a trigger again |
| `alert notifier-add` | `PUT /shodan/alert/{id}/notifier/{notifier_id}` | none | standard | Attach a notifier to an alert |
| `alert notifier-remove` **confirm** | `DELETE /shodan/alert/{id}/notifier/{notifier_id}` | none | standard | Detach a notifier from an alert |

## Notifiers

Pass provider arguments with `--arg NAME=VALUE`, repeated once per argument. `notifier providers` lists what each provider requires.

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `notifier list` | `GET /notifier` | none | standard | Notifiers owned by this account |
| `notifier info` | `GET /notifier/{id}` | none | standard | One notifier's configuration |
| `notifier providers` | `GET /notifier/provider` | none | standard | Notification providers and the arguments each needs |
| `notifier create` | `POST /notifier` | none | standard | Create a notifier; pass provider arguments with --arg key=value |
| `notifier edit` | `PUT /notifier/{id}` | none | standard | Update a notifier's provider arguments |
| `notifier delete` **confirm** | `DELETE /notifier/{id}` | none | standard | Delete a notifier |

## Bulk datasets

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `data list` | `GET /shodan/data` | none | **enterprise** | Bulk datasets available to this account |
| `data files` | `GET /shodan/data/{dataset}` | none | **enterprise** | Download URLs for files in one dataset |

## Organization

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `org info` | `GET /org` | none | **enterprise** | Organization membership and settings |
| `org member-add` | `PUT /org/member/{user}` | none | **enterprise** | Add a member to the organization |
| `org member-remove` **confirm** | `DELETE /org/member/{user}` | none | **enterprise** | Remove a member from the organization |

## Streaming

Feeds write one JSON object per line. Bound every run with `--limit`, `--duration`, or both; a quiet feed otherwise blocks until the idle timeout.

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `stream banners` | `GET /shodan/banners` | none | **enterprise** | Live feed of every banner Shodan collects |
| `stream asn` | `GET /shodan/asn/{asn}` | none | **enterprise** | Live feed filtered to one or more ASNs |
| `stream countries` | `GET /shodan/countries/{countries}` | none | **enterprise** | Live feed filtered to one or more countries |
| `stream ports` | `GET /shodan/ports/{ports}` | none | **enterprise** | Live feed filtered to one or more ports |
| `stream vulns` | `GET /shodan/vulns/{vulns}` | none | **enterprise** | Live feed filtered to one or more vulnerabilities |
| `stream alerts` | `GET /shodan/alert` | none | standard | Live feed for every network alert on this account |
| `stream alert` | `GET /shodan/alert/{id}` | none | standard | Live feed for one network alert |
| `stream custom` | `GET /shodan/custom` | none | **enterprise** | Live feed filtered by an arbitrary search query |

## Trends

Trends returns monthly counts back to 2017. Availability depends on the plan.

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `trends search` | `GET /api/v1/search` | none | standard | Monthly historical counts for a search query, back to 2017 |
| `trends filters` | `GET /api/v1/search/filters` | none | standard | Search filters the Trends service accepts |
| `trends facets` | `GET /api/v1/search/facets` | none | standard | Facets the Trends service accepts |

## Vulnerabilities (CVEDB)

CVEDB replaced the retired Exploits API. These five operations take no API key.

| Command | Method and path | Credits | Access | Summary |
|---|---|---|---|---|
| `cve info` | `GET /cve/{cve_id}` | none | standard | One CVE with CVSS, EPSS, KEV status, and affected products |
| `cve list` | `GET /cves` | none | standard | Search CVEs by product or CPE, newest first |
| `cve cpes` | `GET /cpes` | none | standard | CPE 2.3 strings known for a product name |
| `cve euvd` | `GET /euvd/{euvd_id}` | none | standard | One ENISA EU vulnerability record |
| `cve ghsa` | `GET /ghsa/{ghsa_id}` | none | standard | One GitHub security advisory |

## Service hosts

| Family | Host | Operations |
|---|---|---|
| REST | `api.shodan.io` | 45 |
| Streaming | `stream.shodan.io` | 8 |
| Trends | `trends.shodan.io` | 3 |
| CVEDB | `cvedb.shodan.io` | 5, no API key |

`exploits.shodan.io` is gone. It now returns a 301 to the CVEDB landing page, so the two
old Exploits operations are replaced by the five `cve` operations above.
