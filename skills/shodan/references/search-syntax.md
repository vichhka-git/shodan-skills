# Search syntax

A Shodan query is free text plus `filter:value` terms, combined with an implicit AND:

```bash
python3 scripts/shodan_api.py search count --query 'product:nginx country:DE port:443'
```

Quote the whole query in the shell. Many filter values contain characters the shell would
otherwise eat, and an unquoted space splits the query into separate arguments.

## Building a query without spending credits

`search count` is free and returns the same facet breakdown as `search hosts`. Use it to size
a result set and to iterate on a query, then switch to `search hosts` only when the user needs
the records.

`search tokens` shows how Shodan parsed a query, which is the fastest way to find a typo:

```bash
python3 scripts/shodan_api.py search tokens --query 'country:DE port:443 product:nginx'
```

It returns the filters it recognized, the parsed attributes, the leftover free-text `string`,
and an `errors` list. A filter name that lands in `string` instead of `filters` was misspelled.

## Filters

`search filters` returns the live list, 94 names at the time of writing. The ones that carry
most queries:

| Filter | Matches | Example |
|---|---|---|
| `ip`, `net` | A single address or a CIDR range | `net:8.8.8.0/24` |
| `hostname`, `domain` | Hostname substring, or registered domain | `domain:example.com` |
| `port`, `product`, `version` | Service, software, and version | `product:nginx version:1.25.0` |
| `country`, `city`, `region`, `postal`, `geo` | Location | `country:KH city:"Phnom Penh"` |
| `asn`, `isp`, `org` | Network ownership | `asn:AS15169` |
| `os`, `device`, `cpe` | Platform and device class | `device:router` |
| `vuln`, `has_vuln` | A specific CVE, or any known CVE | `vuln:CVE-2014-0160` |
| `has_ssl`, `ssl.cert.expired`, `ssl.jarm`, `ssl.cert.subject.cn` | TLS properties | `ssl.cert.expired:true` |
| `http.title`, `http.status`, `http.favicon.hash`, `http.waf` | HTTP responses | `http.status:200` |
| `cloud.provider`, `cloud.region`, `cloud.service` | Cloud hosting | `cloud.provider:AWS` |
| `tag`, `has_screenshot`, `has_ipv6` | Shodan annotations | `has_screenshot:true` |

Values with spaces need inner quotes: `city:"Phnom Penh"`. Negate a term with a leading minus:
`product:nginx -port:443`.

## Facets

A facet turns a result set into a count per value, which answers "how many, broken down by
what" without fetching a single record. Pass `facet:size`, comma-separated:

```bash
python3 scripts/shodan_api.py search count --query 'vuln:CVE-2014-0160' --facets country:10,org:5
```

That returns the top ten countries and top five organizations for the match set. `search facets`
returns the live list of 90 facetable fields. The default size is 10 if omitted.

Facets on `count` are free, which makes them the right tool for exposure summaries, country
and ASN breakdowns, and version distributions.

## Pagination

`search hosts` returns 100 results per page and costs one query credit per page. Pages are
1-indexed:

```bash
python3 scripts/shodan_api.py search hosts --query 'product:nginx' --page 2
```

Check the total with `search count` before paginating. A plan's query credits cap how deep
pagination can go, and Shodan limits how far back a result set can be walked regardless of
credits. For a large set, narrow the query with more filters rather than paging through it.

`--minify` trims each banner to its core fields. It does not change the credit cost, but it
makes a page far smaller to read.

## Saved queries

`query list`, `query search`, and `query tags` browse the community directory of saved
queries, which is a good source of working filter combinations. These endpoints have been
returning HTTP 503 upstream; the client reports that as `api` with status 503, and there is
nothing to do about it locally.

## Related operations

- `host info IP` returns everything Shodan holds for one address, for free, and is the right
  call when the user names a specific host rather than a pattern.
- `trends search` returns monthly counts for the same query syntax back to 2017, which answers
  "is this getting better or worse" rather than "how many right now".
- `cve list --product nginx` searches vulnerabilities by product instead of searching hosts,
  and needs no API key.
