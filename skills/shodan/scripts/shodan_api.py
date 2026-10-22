#!/usr/bin/env python3
"""Zero-dependency client for the documented Shodan APIs.

Runs on any Python 3.9+ interpreter using only the standard library, so the
skill works the moment its folder is copied into place.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

VERSION = "1.0.0"
USER_AGENT = f"shodan-skills/{VERSION}"

BASE_URLS = {
    "rest": "https://api.shodan.io",
    "streaming": "https://stream.shodan.io",
    "trends": "https://trends.shodan.io",
    # exploits.shodan.io now 301-redirects to the CVEDB landing page, so the old
    # Exploits API is gone and CVEDB is queried directly. It takes no API key.
    "cvedb": "https://cvedb.shodan.io",
}

CONFIG_PATH = Path(
    os.environ.get("SHODAN_SKILLS_CONFIG")
    or Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    / "shodan-skills"
    / "config.json"
)
LEGACY_CLI_KEY = Path.home() / ".shodan" / "api_key"

CONNECT_TIMEOUT = 30.0
STREAM_IDLE_TIMEOUT = 90.0
MAX_RETRIES = 2
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504, 524}
KEY_PATTERN = re.compile(r"\A[A-Za-z0-9]{32}\Z")


class SkillError(Exception):
    """Failure that maps to a documented error envelope and exit code."""

    kind = "error"
    exit_code = 1

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ConfigError(SkillError):
    kind = "config"
    exit_code = 3


class UsageError(SkillError):
    kind = "usage"
    exit_code = 2


class AuthError(SkillError):
    kind = "auth"
    exit_code = 4


class AccessError(SkillError):
    kind = "access"
    exit_code = 5


class CreditsError(SkillError):
    kind = "credits"
    exit_code = 6


class ApiError(SkillError):
    kind = "api"
    exit_code = 7


class NetworkError(SkillError):
    kind = "network"
    exit_code = 8


_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    if value and len(value) >= 8:
        _secrets.add(value)


def redact(text: str) -> str:
    """Strip registered secrets. Safe for response bodies, which may legitimately
    contain a key= parameter inside a scanned banner."""
    for secret in _secrets:
        text = text.replace(secret, "<redacted>")
    return text


def redact_url(text: str) -> str:
    """Strip secrets and any key= parameter. Only for URLs this client builds."""
    return re.sub(r"(?i)(key=)[^&\s\"']+", r"\1<redacted>", redact(text))


@dataclass
class Credential:
    key: str
    source: str


def read_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Cannot read {CONFIG_PATH}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{CONFIG_PATH} must contain a JSON object.")
    return data


def resolve_credential() -> Credential:
    """Resolve the API key from env, then this skill's config, then the Shodan CLI."""
    env_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if env_key:
        return Credential(env_key, "env:SHODAN_API_KEY")

    stored = read_config().get("api_key")
    if isinstance(stored, str) and stored.strip():
        warn_if_world_readable(CONFIG_PATH)
        return Credential(stored.strip(), f"file:{CONFIG_PATH}")

    if LEGACY_CLI_KEY.exists():
        try:
            legacy = LEGACY_CLI_KEY.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"Cannot read {LEGACY_CLI_KEY}: {exc}") from exc
        if legacy:
            return Credential(legacy, f"file:{LEGACY_CLI_KEY}")

    raise ConfigError(
        "No Shodan API key found. Run 'config set' to store one, or export SHODAN_API_KEY."
    )


def warn_if_world_readable(path: Path) -> None:
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        print(
            f"warning: {path} is readable by other users; run 'config repair' to fix permissions.",
            file=sys.stderr,
        )


def write_key(key: str) -> None:
    """Persist the key with owner-only permissions on both file and parent directory."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_PATH.parent, 0o700)
    payload = read_config()
    payload["api_key"] = key
    # Create with 0600 before writing so the key is never briefly world-readable.
    fd = os.open(str(CONFIG_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(CONFIG_PATH, 0o600)


def mask(key: str) -> str:
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise UsageError(f"Not a valid IP address: {value!r}") from exc


def validate_net(value: str) -> str:
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise UsageError(f"Not a valid IP or CIDR range: {value!r}") from exc
    return validate_ip(value)


def validate_ip_list(value: str) -> str:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise UsageError("Expected at least one IP address.")
    return ",".join(validate_net(item) for item in items)


HOSTNAME_RE = re.compile(r"\A(?=.{1,253}\Z)(?!-)[A-Za-z0-9_-]{1,63}(\.(?!-)[A-Za-z0-9_-]{1,63})*\Z")


def validate_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".")
    if not HOSTNAME_RE.match(candidate):
        raise UsageError(f"Not a valid hostname: {value!r}")
    return candidate


def validate_hostname_list(value: str) -> str:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise UsageError("Expected at least one hostname.")
    return ",".join(validate_hostname(item) for item in items)


def validate_asn(value: str) -> str:
    candidate = value.strip().upper()
    if candidate.startswith("AS"):
        candidate = candidate[2:]
    items = [item for item in candidate.split(",") if item]
    if not items or not all(item.isdigit() for item in items):
        raise UsageError(f"Not a valid ASN list: {value!r} (use 3303 or AS3303,AS12345)")
    return ",".join(f"AS{item}" for item in items)


def validate_countries(value: str) -> str:
    items = [item.strip().upper() for item in value.split(",") if item.strip()]
    if not items or not all(re.fullmatch(r"[A-Z]{2}", item) for item in items):
        raise UsageError(f"Expected ISO 3166-1 alpha-2 codes: {value!r}")
    return ",".join(items)


def validate_ports(value: str) -> str:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if not items:
        raise UsageError("Expected at least one port.")
    for item in items:
        if not item.isdigit() or not 1 <= int(item) <= 65535:
            raise UsageError(f"Port out of range 1-65535: {item!r}")
    return ",".join(items)


def validate_port(value: str) -> str:
    if "," in value:
        raise UsageError(f"Expected a single port, got {value!r}")
    return validate_ports(value)


def validate_vulns(value: str) -> str:
    items = [item.strip().upper() for item in value.split(",") if item.strip()]
    if not items or not all(re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{2,40}", item) for item in items):
        raise UsageError(f"Expected vulnerability identifiers such as CVE-2014-0160: {value!r}")
    return ",".join(items)


def validate_token(value: str) -> str:
    """Accept identifiers that are safe to interpolate into a URL path."""
    candidate = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}", candidate):
        raise UsageError(f"Not a valid identifier: {value!r}")
    return candidate


def validate_service(value: str) -> str:
    """An alert trigger ignore target, written as ip:port."""
    candidate = value.strip()
    if ":" not in candidate:
        raise UsageError(f"Expected ip:port, got {value!r}")
    host, _, port = candidate.rpartition(":")
    return f"{validate_ip(host)}:{validate_ports(port)}"


def validate_text(value: str) -> str:
    if not value.strip():
        raise UsageError("Expected a non-empty value.")
    return value


def validate_int(value: str) -> str:
    if not re.fullmatch(r"-?\d{1,9}", value.strip()):
        raise UsageError(f"Expected an integer: {value!r}")
    return value.strip()


VALIDATORS: dict[str, Callable[[str], str]] = {
    "ip": validate_ip,
    "ip_list": validate_ip_list,
    "hostname_list": validate_hostname_list,
    "domain": validate_hostname,
    "asn": validate_asn,
    "countries": validate_countries,
    "ports": validate_ports,
    "port": validate_port,
    "vulns": validate_vulns,
    "token": validate_token,
    "service": validate_service,
    "text": validate_text,
    "int": validate_int,
}


@dataclass(frozen=True)
class Param:
    name: str
    kind: str
    help: str
    required: bool = False
    repeat: bool = False


@dataclass(frozen=True)
class Operation:
    group: str
    action: str
    api: str
    method: str
    path: str
    summary: str
    path_params: tuple[Param, ...] = ()
    query_params: tuple[Param, ...] = ()
    body_params: tuple[Param, ...] = ()
    flags: tuple[Param, ...] = ()
    access: str = "standard"
    credits: str = "none"
    destructive: bool = False
    body_style: str = "form"
    stream: bool = False
    needs_key: bool = True

    @property
    def name(self) -> str:
        return f"{self.group} {self.action}"


def P(name: str, kind: str, help: str, required: bool = False, repeat: bool = False) -> Param:
    return Param(name, kind, help, required, repeat)


QUERY = P("query", "text", "Shodan search query", required=True)
FACETS = P("facets", "text", "Comma-separated facet list, e.g. country:10,port:5")
PAGE = P("page", "int", "1-indexed result page")

OPERATIONS: tuple[Operation, ...] = (
    Operation("account", "api-info", "rest", "GET", "/api-info",
              "Plan, query credits, scan credits, and monitored-IP limits"),
    Operation("account", "profile", "rest", "GET", "/account/profile",
              "Membership and profile metadata, not credit balances"),

    Operation("host", "info", "rest", "GET", "/shodan/host/{ip}",
              "All banners Shodan holds for one IP",
              path_params=(P("ip", "ip", "Target IP address", required=True),),
              flags=(P("history", "flag", "Include historical banners"),
                     P("minify", "flag", "Trim banner detail"))),

    Operation("search", "hosts", "rest", "GET", "/shodan/host/search",
              "Search the host index; consumes 1 query credit per page",
              query_params=(QUERY, FACETS, PAGE),
              flags=(P("minify", "flag", "Trim banner detail"),),
              credits="query"),
    Operation("search", "count", "rest", "GET", "/shodan/host/count",
              "Result count and facets without consuming query credits",
              query_params=(QUERY, FACETS)),
    Operation("search", "facets", "rest", "GET", "/shodan/host/search/facets",
              "Facet names available to search queries"),
    Operation("search", "filters", "rest", "GET", "/shodan/host/search/filters",
              "Search filter names available to queries"),
    Operation("search", "tokens", "rest", "GET", "/shodan/host/search/tokens",
              "Break a query into its parsed filters and errors",
              query_params=(QUERY,)),

    Operation("query", "list", "rest", "GET", "/shodan/query",
              "Saved search queries from the community directory",
              query_params=(PAGE, P("sort", "text", "Sort by votes or timestamp"),
                            P("order", "text", "asc or desc"))),
    Operation("query", "search", "rest", "GET", "/shodan/query/search",
              "Search the saved-query directory",
              query_params=(QUERY, PAGE)),
    Operation("query", "tags", "rest", "GET", "/shodan/query/tags",
              "Most popular tags in the saved-query directory",
              query_params=(P("size", "int", "Number of tags to return"),)),

    Operation("dns", "resolve", "rest", "GET", "/dns/resolve",
              "Resolve hostnames to IP addresses",
              query_params=(P("hostnames", "hostname_list", "Comma-separated hostnames",
                              required=True),)),
    Operation("dns", "reverse", "rest", "GET", "/dns/reverse",
              "Reverse-resolve IP addresses to hostnames",
              query_params=(P("ips", "ip_list", "Comma-separated IP addresses", required=True),)),
    Operation("dns", "domain", "rest", "GET", "/dns/domain/{domain}",
              "Subdomains and DNS records for a domain; consumes 1 query credit",
              path_params=(P("domain", "domain", "Registered domain name", required=True),),
              query_params=(P("type", "text", "Record type filter, e.g. A or MX"), PAGE),
              flags=(P("history", "flag", "Include historical records"),),
              credits="query"),

    Operation("tools", "myip", "rest", "GET", "/tools/myip",
              "The external IP address Shodan sees for this caller"),
    Operation("tools", "httpheaders", "rest", "GET", "/tools/httpheaders",
              "HTTP headers this caller sends"),

    Operation("scan", "ports", "rest", "GET", "/shodan/ports",
              "Ports Shodan crawls"),
    Operation("scan", "protocols", "rest", "GET", "/shodan/protocols",
              "Protocols available to on-demand scans"),
    Operation("scan", "list", "rest", "GET", "/shodan/scans",
              "Scans submitted by this account"),
    Operation("scan", "status", "rest", "GET", "/shodan/scan/{id}",
              "Progress of one submitted scan",
              path_params=(P("id", "token", "Scan identifier", required=True),)),
    Operation("scan", "submit", "rest", "POST", "/shodan/scan",
              "Request an on-demand scan; consumes scan credits",
              body_params=(P("ips", "ip_list", "Comma-separated IPs or CIDR ranges",
                             required=True),
                           P("service", "text", "Restrict to port/protocol pairs, repeatable",
                             repeat=True)),
              credits="scan"),
    Operation("scan", "internet", "rest", "POST", "/shodan/scan/internet",
              "Crawl the whole internet for one port and protocol",
              body_params=(P("port", "port", "Single port to crawl", required=True),
                           P("protocol", "text", "Protocol name from 'scan protocols'",
                             required=True)),
              access="enterprise", credits="unknown", destructive=True),

    Operation("alert", "list", "rest", "GET", "/shodan/alert/info",
              "Network alerts owned by this account"),
    Operation("alert", "info", "rest", "GET", "/shodan/alert/{id}/info",
              "One network alert and its triggers",
              path_params=(P("id", "token", "Alert identifier", required=True),)),
    Operation("alert", "triggers", "rest", "GET", "/shodan/alert/triggers",
              "Trigger types that alerts can enable"),
    Operation("alert", "create", "rest", "POST", "/shodan/alert",
              "Create a network alert for a set of IPs",
              body_params=(P("name", "text", "Human-readable alert name", required=True),
                           P("ips", "ip_list", "Comma-separated IPs or CIDR ranges",
                             required=True),
                           P("expires", "int", "Lifetime in seconds, 0 for permanent")),
              body_style="json"),
    Operation("alert", "edit", "rest", "POST", "/shodan/alert/{id}",
              "Replace the IP list monitored by an alert",
              path_params=(P("id", "token", "Alert identifier", required=True),),
              body_params=(P("ips", "ip_list", "Replacement IPs or CIDR ranges", required=True),),
              body_style="json"),
    Operation("alert", "delete", "rest", "DELETE", "/shodan/alert/{id}",
              "Delete a network alert",
              path_params=(P("id", "token", "Alert identifier", required=True),),
              destructive=True),
    Operation("alert", "trigger-enable", "rest", "PUT",
              "/shodan/alert/{id}/trigger/{trigger}",
              "Enable a trigger on an alert",
              path_params=(P("id", "token", "Alert identifier", required=True),
                           P("trigger", "token", "Trigger name", required=True))),
    Operation("alert", "trigger-disable", "rest", "DELETE",
              "/shodan/alert/{id}/trigger/{trigger}",
              "Disable a trigger on an alert",
              path_params=(P("id", "token", "Alert identifier", required=True),
                           P("trigger", "token", "Trigger name", required=True)),
              destructive=True),
    Operation("alert", "trigger-ignore", "rest", "PUT",
              "/shodan/alert/{id}/trigger/{trigger}/ignore/{service}",
              "Stop one service from firing a trigger",
              path_params=(P("id", "token", "Alert identifier", required=True),
                           P("trigger", "token", "Trigger name", required=True),
                           P("service", "service", "Target as ip:port", required=True))),
    Operation("alert", "trigger-unignore", "rest", "DELETE",
              "/shodan/alert/{id}/trigger/{trigger}/ignore/{service}",
              "Let an ignored service fire a trigger again",
              path_params=(P("id", "token", "Alert identifier", required=True),
                           P("trigger", "token", "Trigger name", required=True),
                           P("service", "service", "Target as ip:port", required=True))),
    Operation("alert", "notifier-add", "rest", "PUT",
              "/shodan/alert/{id}/notifier/{notifier_id}",
              "Attach a notifier to an alert",
              path_params=(P("id", "token", "Alert identifier", required=True),
                           P("notifier_id", "token", "Notifier identifier", required=True))),
    Operation("alert", "notifier-remove", "rest", "DELETE",
              "/shodan/alert/{id}/notifier/{notifier_id}",
              "Detach a notifier from an alert",
              path_params=(P("id", "token", "Alert identifier", required=True),
                           P("notifier_id", "token", "Notifier identifier", required=True)),
              destructive=True),

    Operation("notifier", "list", "rest", "GET", "/notifier",
              "Notifiers owned by this account"),
    Operation("notifier", "info", "rest", "GET", "/notifier/{id}",
              "One notifier's configuration",
              path_params=(P("id", "token", "Notifier identifier", required=True),)),
    Operation("notifier", "providers", "rest", "GET", "/notifier/provider",
              "Notification providers and the arguments each needs"),
    Operation("notifier", "create", "rest", "POST", "/notifier",
              "Create a notifier; pass provider arguments with --arg key=value",
              body_params=(P("provider", "token", "Provider name from 'notifier providers'",
                             required=True),
                           P("description", "text", "Human-readable description")),
              flags=(P("arg", "kv", "Provider argument as NAME=VALUE, repeatable"),)),
    Operation("notifier", "edit", "rest", "PUT", "/notifier/{id}",
              "Update a notifier's provider arguments",
              path_params=(P("id", "token", "Notifier identifier", required=True),),
              body_params=(P("description", "text", "Human-readable description"),),
              flags=(P("arg", "kv", "Provider argument as NAME=VALUE, repeatable"),)),
    Operation("notifier", "delete", "rest", "DELETE", "/notifier/{id}",
              "Delete a notifier",
              path_params=(P("id", "token", "Notifier identifier", required=True),),
              destructive=True),

    Operation("data", "list", "rest", "GET", "/shodan/data",
              "Bulk datasets available to this account",
              access="enterprise"),
    Operation("data", "files", "rest", "GET", "/shodan/data/{dataset}",
              "Download URLs for files in one dataset",
              path_params=(P("dataset", "token", "Dataset name", required=True),),
              access="enterprise"),

    Operation("org", "info", "rest", "GET", "/org",
              "Organization membership and settings",
              access="enterprise"),
    Operation("org", "member-add", "rest", "PUT", "/org/member/{user}",
              "Add a member to the organization",
              path_params=(P("user", "token", "Shodan username or email", required=True),),
              query_params=(P("notify", "text", "true to email the invitation"),),
              access="enterprise"),
    Operation("org", "member-remove", "rest", "DELETE", "/org/member/{user}",
              "Remove a member from the organization",
              path_params=(P("user", "token", "Shodan username or email", required=True),),
              access="enterprise", destructive=True),

    Operation("stream", "banners", "streaming", "GET", "/shodan/banners",
              "Live feed of every banner Shodan collects",
              access="enterprise", stream=True),
    Operation("stream", "asn", "streaming", "GET", "/shodan/asn/{asn}",
              "Live feed filtered to one or more ASNs",
              path_params=(P("asn", "asn", "Comma-separated ASNs, e.g. AS3303", required=True),),
              access="enterprise", stream=True),
    Operation("stream", "countries", "streaming", "GET", "/shodan/countries/{countries}",
              "Live feed filtered to one or more countries",
              path_params=(P("countries", "countries", "Comma-separated ISO country codes",
                             required=True),),
              access="enterprise", stream=True),
    Operation("stream", "ports", "streaming", "GET", "/shodan/ports/{ports}",
              "Live feed filtered to one or more ports",
              path_params=(P("ports", "ports", "Comma-separated ports", required=True),),
              access="enterprise", stream=True),
    Operation("stream", "vulns", "streaming", "GET", "/shodan/vulns/{vulns}",
              "Live feed filtered to one or more vulnerabilities",
              path_params=(P("vulns", "vulns", "Comma-separated CVE identifiers", required=True),),
              access="enterprise", stream=True),
    Operation("stream", "alerts", "streaming", "GET", "/shodan/alert",
              "Live feed for every network alert on this account",
              stream=True),
    Operation("stream", "alert", "streaming", "GET", "/shodan/alert/{id}",
              "Live feed for one network alert",
              path_params=(P("id", "token", "Alert identifier", required=True),),
              stream=True),
    Operation("stream", "custom", "streaming", "GET", "/shodan/custom",
              "Live feed filtered by an arbitrary search query",
              query_params=(QUERY,), access="enterprise", stream=True),

    Operation("trends", "search", "trends", "GET", "/api/v1/search",
              "Monthly historical counts for a search query, back to 2017",
              query_params=(QUERY, FACETS)),
    Operation("trends", "filters", "trends", "GET", "/api/v1/search/filters",
              "Search filters the Trends service accepts"),
    Operation("trends", "facets", "trends", "GET", "/api/v1/search/facets",
              "Facets the Trends service accepts"),

    # CVEDB replaced the retired Exploits API and needs no API key.
    Operation("cve", "info", "cvedb", "GET", "/cve/{cve_id}",
              "One CVE with CVSS, EPSS, KEV status, and affected products",
              path_params=(P("cve_id", "token", "CVE identifier, e.g. CVE-2014-0160",
                             required=True),),
              needs_key=False),
    Operation("cve", "list", "cvedb", "GET", "/cves",
              "Search CVEs by product or CPE, newest first",
              query_params=(P("product", "text", "Product name, e.g. nginx"),
                            P("cpe23", "text", "CPE 2.3 string, e.g. cpe:2.3:a:f5:nginx:1.25.0"),
                            P("start_date", "text", "Earliest publish date, YYYY-MM-DD"),
                            P("end_date", "text", "Latest publish date, YYYY-MM-DD"),
                            P("skip", "int", "Results to skip"),
                            P("limit", "int", "Maximum results to return")),
              flags=(P("count", "flag", "Return only the total count"),
                     P("is_kev", "flag", "Only CISA known-exploited vulnerabilities"),
                     P("sort_by_epss", "flag", "Sort by exploit-prediction score")),
              needs_key=False),
    Operation("cve", "cpes", "cvedb", "GET", "/cpes",
              "CPE 2.3 strings known for a product name",
              query_params=(P("product", "text", "Product name", required=True),
                            P("skip", "int", "Results to skip"),
                            P("limit", "int", "Maximum results to return")),
              flags=(P("count", "flag", "Return only the total count"),),
              needs_key=False),
    Operation("cve", "euvd", "cvedb", "GET", "/euvd/{euvd_id}",
              "One ENISA EU vulnerability record",
              path_params=(P("euvd_id", "token", "EUVD identifier, e.g. EUVD-2025-15964",
                             required=True),),
              needs_key=False),
    Operation("cve", "ghsa", "cvedb", "GET", "/ghsa/{ghsa_id}",
              "One GitHub security advisory",
              path_params=(P("ghsa_id", "token", "GHSA identifier, e.g. GHSA-5mg8-w23w-74h3",
                             required=True),),
              needs_key=False),
)

OPERATIONS_BY_NAME = {op.name: op for op in OPERATIONS}


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes = b""
    raw: Any = None


def build_url(op: Operation, path: str, params: list[tuple[str, str]]) -> str:
    base = BASE_URLS[op.api] + path
    return f"{base}?{urllib.parse.urlencode(params)}" if params else base


def send(
    op: Operation,
    url: str,
    *,
    body: bytes | None,
    content_type: str | None,
    timeout: float,
    stream: bool = False,
) -> Any:
    request = urllib.request.Request(url, data=body, method=op.method)
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Accept", "application/json")
    if content_type:
        request.add_header("Content-Type", content_type)

    attempts = MAX_RETRIES + 1 if op.method == "GET" and not stream else 1
    for attempt in range(attempts):
        try:
            handle = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 - fixed https hosts
        except urllib.error.HTTPError as exc:
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            if exc.code in RETRYABLE_STATUS and attempt + 1 < attempts:
                time.sleep(backoff(attempt, retry_after))
                continue
            raise translate_http_error(exc) from None
        except urllib.error.URLError as exc:
            if attempt + 1 < attempts:
                time.sleep(backoff(attempt, None))
                continue
            raise NetworkError(f"Cannot reach {BASE_URLS[op.api]}: {redact_url(str(exc.reason))}") from None
        except TimeoutError as exc:
            if attempt + 1 < attempts:
                time.sleep(backoff(attempt, None))
                continue
            raise NetworkError("Request timed out.") from exc
        return handle
    raise NetworkError("Request failed after retries.")


def backoff(attempt: int, retry_after: str | None) -> float:
    if retry_after and retry_after.strip().isdigit():
        return min(float(retry_after.strip()), 10.0)
    return min(0.5 * (2**attempt), 8.0)


def translate_http_error(exc: urllib.error.HTTPError) -> SkillError:
    detail = ""
    try:
        payload = json.loads(exc.read().decode("utf-8", "replace"))
        if isinstance(payload, dict):
            detail = str(payload.get("error") or payload.get("message") or "")
    except (ValueError, OSError):
        detail = ""
    message = redact_url(detail or exc.reason or "Shodan returned an error.")

    if exc.code in (401, 403):
        lowered = message.lower()
        if "membership" in lowered or "upgrade" in lowered or "api plan" in lowered:
            return AccessError(message, exc.code)
        if exc.code == 403:
            return AccessError(message, exc.code)
        return AuthError(message, exc.code)
    if exc.code == 402:
        return CreditsError(message, exc.code)
    if exc.code == 429:
        return ApiError(f"Rate limited by Shodan: {message}", exc.code)
    return ApiError(message, exc.code)


def parse_json(handle: Any) -> Any:
    raw = handle.read()
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise ApiError(f"Shodan returned a non-JSON body: {redact_url(raw[:200].decode('utf-8', 'replace'))}") from exc


def iter_stream(handle: Any) -> Iterator[Any]:
    """Yield records from a Shodan JSON Lines feed, skipping keep-alive blanks."""
    for line in handle:
        text = line.decode("utf-8", "replace").strip()
        if not text:
            continue
        try:
            yield json.loads(text)
        except ValueError:
            continue


@dataclass
class Plan:
    op: Operation
    url: str
    display_url: str
    body: bytes | None = None
    content_type: str | None = None
    notes: list[str] = field(default_factory=list)


def collect_kv(values: list[str] | None) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise UsageError(f"Expected NAME=VALUE, got {item!r}")
        key, _, value = item.partition("=")
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key):
            raise UsageError(f"Not a valid argument name: {key!r}")
        pairs[key] = value
    return pairs


def build_plan(op: Operation, args: argparse.Namespace, key: str | None) -> Plan:
    path = op.path
    for param in op.path_params:
        raw = getattr(args, param.name.replace("-", "_"))
        value = VALIDATORS[param.kind](raw)
        path = path.replace(f"{{{param.name}}}", urllib.parse.quote(value, safe=""))

    query: list[tuple[str, str]] = [("key", key)] if key else []
    for param in op.query_params:
        raw = getattr(args, param.name.replace("-", "_"), None)
        if raw is None:
            continue
        query.append((param.name, VALIDATORS[param.kind](raw)))
    for flag in op.flags:
        if flag.kind == "flag" and getattr(args, flag.name.replace("-", "_"), False):
            query.append((flag.name, "true"))

    body_fields: list[tuple[str, str]] = []
    json_body: dict[str, Any] = {}
    for param in op.body_params:
        raw = getattr(args, param.name.replace("-", "_"), None)
        if raw is None or raw == []:
            continue
        if param.repeat:
            for item in raw:
                body_fields.append((param.name, VALIDATORS[param.kind](item)))
            continue
        value = VALIDATORS[param.kind](raw)
        if op.body_style == "json":
            json_body[param.name] = value
        else:
            body_fields.append((param.name, value))

    if any(flag.kind == "kv" for flag in op.flags):
        for name, value in collect_kv(getattr(args, "arg", None)).items():
            body_fields.append((name, value))
            register_secret(value)

    body: bytes | None = None
    content_type: str | None = None
    if op.body_style == "json" and json_body:
        body = json.dumps(shape_json_body(op, json_body)).encode("utf-8")
        content_type = "application/json"
    elif body_fields:
        body = urllib.parse.urlencode(body_fields).encode("utf-8")
        content_type = "application/x-www-form-urlencoded"
    elif op.method in ("POST", "PUT"):
        body = b""

    url = build_url(op, path, query)
    display = redact_url(url)
    notes = []
    if op.credits != "none":
        notes.append(f"consumes {op.credits} credits")
    if op.access != "standard":
        notes.append(f"requires {op.access} entitlement")
    if op.destructive:
        notes.append("destructive")
    return Plan(op, url, display, body, content_type, notes)


def shape_json_body(op: Operation, values: dict[str, Any]) -> dict[str, Any]:
    """Nest alert fields into the filters object the alert endpoints expect."""
    if op.group != "alert":
        return values
    shaped: dict[str, Any] = {}
    if "name" in values:
        shaped["name"] = values["name"]
    if "ips" in values:
        shaped["filters"] = {"ip": values["ips"].split(",")}
    if "expires" in values:
        shaped["expires"] = int(values["expires"])
    return shaped


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(redact(json.dumps(payload, indent=2, sort_keys=True)) + "\n")
    sys.stdout.flush()


def success(command: str, data: Any, **extra: Any) -> None:
    emit({"ok": True, "command": command, "data": data, **extra})


def failure(command: str, error: SkillError) -> int:
    body: dict[str, Any] = {"type": error.kind, "message": redact_url(str(error))}
    if error.status:
        body["status"] = error.status
    emit({"ok": False, "command": command, "error": body})
    return error.exit_code


def cmd_config_set(args: argparse.Namespace) -> int:
    if args.stdin or not sys.stdin.isatty():
        key = sys.stdin.readline().strip()
    else:
        key = getpass.getpass("Shodan API key (not echoed): ").strip()
    if not key:
        raise ConfigError("No key supplied.")
    if not KEY_PATTERN.match(key):
        raise ConfigError("A Shodan API key is 32 alphanumeric characters.")
    register_secret(key)

    verified: Any = None
    if not args.no_verify:
        handle = send(
            OPERATIONS_BY_NAME["account api-info"],
            f"{BASE_URLS['rest']}/api-info?{urllib.parse.urlencode([('key', key)])}",
            body=None, content_type=None, timeout=CONNECT_TIMEOUT,
        )
        verified = parse_json(handle)

    write_key(key)
    success("config set", {
        "path": str(CONFIG_PATH),
        "permissions": "0600",
        "key": mask(key),
        "verified": verified is not None,
        "plan": (verified or {}).get("plan"),
    })
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    sources = []
    if os.environ.get("SHODAN_API_KEY", "").strip():
        sources.append("env:SHODAN_API_KEY")
    if isinstance(read_config().get("api_key"), str):
        sources.append(f"file:{CONFIG_PATH}")
    if LEGACY_CLI_KEY.exists():
        sources.append(f"file:{LEGACY_CLI_KEY}")

    data: dict[str, Any] = {
        "config_path": str(CONFIG_PATH),
        "config_exists": CONFIG_PATH.exists(),
        "available_sources": sources,
        "active_source": None,
        "key": None,
    }
    if CONFIG_PATH.exists():
        data["config_permissions"] = oct(CONFIG_PATH.stat().st_mode & 0o777)
    try:
        credential = resolve_credential()
    except ConfigError:
        pass
    else:
        register_secret(credential.key)
        data["active_source"] = credential.source
        data["key"] = mask(credential.key)
    success("config show", data)
    return 0


def cmd_config_test(args: argparse.Namespace) -> int:
    credential = resolve_credential()
    register_secret(credential.key)
    op = OPERATIONS_BY_NAME["account api-info"]
    handle = send(
        op,
        f"{BASE_URLS['rest']}/api-info?{urllib.parse.urlencode([('key', credential.key)])}",
        body=None, content_type=None, timeout=CONNECT_TIMEOUT,
    )
    info = parse_json(handle) or {}
    success("config test", {
        "source": credential.source,
        "key": mask(credential.key),
        "plan": info.get("plan"),
        "query_credits": info.get("query_credits"),
        "scan_credits": info.get("scan_credits"),
        "monitored_ips": info.get("monitored_ips"),
        "limits": info.get("usage_limits"),
    })
    return 0


def cmd_config_repair(args: argparse.Namespace) -> int:
    if not CONFIG_PATH.exists():
        raise ConfigError(f"{CONFIG_PATH} does not exist.")
    os.chmod(CONFIG_PATH.parent, 0o700)
    os.chmod(CONFIG_PATH, 0o600)
    success("config repair", {
        "path": str(CONFIG_PATH),
        "permissions": oct(CONFIG_PATH.stat().st_mode & 0o777),
        "directory_permissions": oct(CONFIG_PATH.parent.stat().st_mode & 0o777),
    })
    return 0


def cmd_config_remove(args: argparse.Namespace) -> int:
    existed = CONFIG_PATH.exists()
    if existed:
        payload = read_config()
        payload.pop("api_key", None)
        if payload:
            write_key_free(payload)
        else:
            CONFIG_PATH.unlink()
    success("config remove", {"path": str(CONFIG_PATH), "removed": existed})
    return 0


def write_key_free(payload: dict[str, Any]) -> None:
    fd = os.open(str(CONFIG_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def cmd_operations(args: argparse.Namespace) -> int:
    success("operations", [
        {
            "command": op.name,
            "api": op.api,
            "method": op.method,
            "path": op.path,
            "access": op.access,
            "credits": op.credits,
            "destructive": op.destructive,
            "summary": op.summary,
        }
        for op in OPERATIONS
    ], count=len(OPERATIONS))
    return 0


def run_operation(op: Operation, args: argparse.Namespace) -> int:
    if op.destructive and not args.confirm and not args.dry_run:
        raise UsageError(
            f"'{op.name}' is destructive. Re-run with --confirm once the user has asked for it."
        )

    key: str | None = None
    if op.needs_key:
        credential = resolve_credential()
        register_secret(credential.key)
        key = credential.key
    plan = build_plan(op, args, key)

    if args.dry_run:
        success(op.name, None, dry_run={
            "method": op.method,
            "url": plan.display_url,
            "body": plan.body.decode("utf-8", "replace") if plan.body else None,
            "access": op.access,
            "credits": op.credits,
            "destructive": op.destructive,
            "notes": plan.notes,
        })
        return 0

    if op.stream:
        return run_stream(op, plan, args)

    handle = send(op, plan.url, body=plan.body, content_type=plan.content_type,
                  timeout=args.timeout)
    data = parse_json(handle)
    extra: dict[str, Any] = {}
    if plan.notes:
        extra["notes"] = plan.notes
    success(op.name, data, **extra)
    return 0


def run_stream(op: Operation, plan: Plan, args: argparse.Namespace) -> int:
    """Write one JSON record per line until the limit, duration, or the feed ends."""
    # A quiet feed blocks in read(), so the socket timeout is what enforces --duration.
    read_timeout = min(args.idle_timeout, args.duration) if args.duration else args.idle_timeout
    handle = send(op, plan.url, body=None, content_type=None,
                  timeout=read_timeout, stream=True)
    deadline = time.monotonic() + args.duration if args.duration else None
    written = 0
    stopped = "feed-closed"
    try:
        for record in iter_stream(handle):
            sys.stdout.write(redact(json.dumps(record, sort_keys=True)) + "\n")
            sys.stdout.flush()
            written += 1
            if args.limit and written >= args.limit:
                stopped = "limit-reached"
                break
            if deadline and time.monotonic() >= deadline:
                stopped = "duration-reached"
                break
    except KeyboardInterrupt:
        stopped = "interrupted"
    except (socket.timeout, TimeoutError):
        stopped = "duration-reached" if deadline else "idle-timeout"
    except OSError as exc:
        raise NetworkError(f"Stream read failed: {redact_url(str(exc))}") from None
    finally:
        handle.close()
    print(json.dumps({"ok": True, "command": op.name, "records": written, "stopped": stopped}),
          file=sys.stderr)
    return 0


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:
        emit({"ok": False, "command": self.prog, "error": {"type": "usage",
                                                           "message": redact_url(message)}})
        raise SystemExit(UsageError.exit_code)


def add_runtime_options(parser: argparse.ArgumentParser, *, stream: bool) -> None:
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the request that would be sent, then exit")
    parser.add_argument("--confirm", action="store_true",
                        help="Authorize a destructive operation")
    parser.add_argument("--timeout", type=float, default=CONNECT_TIMEOUT,
                        help=f"Per-request timeout in seconds (default {CONNECT_TIMEOUT:g})")
    if stream:
        parser.add_argument("--limit", type=int, default=0,
                            help="Stop after this many records (0 means no limit)")
        parser.add_argument("--duration", type=float, default=0.0,
                            help="Stop after this many seconds (0 means no limit)")
        parser.add_argument("--idle-timeout", type=float, default=STREAM_IDLE_TIMEOUT,
                            help=f"Give up after this long with no data (default {STREAM_IDLE_TIMEOUT:g})")


def build_parser() -> Parser:
    parser = Parser(
        prog="shodan_api.py",
        description="Zero-dependency client for the documented Shodan APIs.",
    )
    parser.add_argument("--version", action="version", version=f"shodan-skills {VERSION}")
    groups = parser.add_subparsers(dest="group", metavar="GROUP")

    config = groups.add_parser("config", help="Store and inspect the API key")
    config_actions = config.add_subparsers(dest="action", metavar="ACTION")
    set_parser = config_actions.add_parser(
        "set", help="Store an API key read from a prompt or stdin, never from argv")
    set_parser.add_argument("--stdin", action="store_true",
                            help="Read the key from stdin instead of prompting")
    set_parser.add_argument("--no-verify", action="store_true",
                            help="Skip the /api-info check before writing")
    set_parser.set_defaults(handler=cmd_config_set)
    config_actions.add_parser(
        "show", help="Show the active key source and masked key"
    ).set_defaults(handler=cmd_config_show)
    config_actions.add_parser(
        "test", help="Verify the resolved key against /api-info"
    ).set_defaults(handler=cmd_config_test)
    config_actions.add_parser(
        "repair", help="Reset config file and directory to owner-only permissions"
    ).set_defaults(handler=cmd_config_repair)
    config_actions.add_parser(
        "remove", help="Delete the stored key"
    ).set_defaults(handler=cmd_config_remove)

    groups.add_parser(
        "operations", help="List every supported operation as JSON"
    ).set_defaults(handler=cmd_operations)

    by_group: dict[str, list[Operation]] = {}
    for op in OPERATIONS:
        by_group.setdefault(op.group, []).append(op)

    for group_name, ops in by_group.items():
        group_parser = groups.add_parser(group_name, help=f"{group_name} operations")
        actions = group_parser.add_subparsers(dest="action", metavar="ACTION")
        for op in ops:
            leaf = actions.add_parser(op.action, help=op.summary, description=op.summary)
            for param in op.path_params:
                leaf.add_argument(param.name, help=param.help)
            for param in (*op.query_params, *op.body_params):
                option = f"--{param.name.replace('_', '-')}"
                if param.repeat:
                    leaf.add_argument(option, dest=param.name, action="append",
                                      help=param.help)
                else:
                    leaf.add_argument(option, dest=param.name, required=param.required,
                                      help=param.help)
            for flag in op.flags:
                option = f"--{flag.name.replace('_', '-')}"
                if flag.kind == "flag":
                    leaf.add_argument(option, dest=flag.name, action="store_true",
                                      help=flag.help)
                else:
                    leaf.add_argument(option, dest=flag.name, action="append",
                                      help=flag.help)
            add_runtime_options(leaf, stream=op.stream)
            leaf.set_defaults(handler=lambda args, op=op: run_operation(op, args))

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return UsageError.exit_code

    command = " ".join(part for part in (getattr(args, "group", None),
                                         getattr(args, "action", None)) if part)
    try:
        return handler(args)
    except SkillError as error:
        return failure(command, error)
    except KeyboardInterrupt:
        return failure(command, SkillError("Interrupted."))


if __name__ == "__main__":
    sys.exit(main())
