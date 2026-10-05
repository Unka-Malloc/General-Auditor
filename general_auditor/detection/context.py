"""Contextual privacy signals for endpoints, identities, and runtime values."""

from collections.abc import Iterator, Mapping
from fnmatch import fnmatchcase
import ipaddress
import re
from urllib.parse import urlsplit, unquote
import base64
import binascii

from .providers import _binding_matches, is_placeholder, normalize_key
from .types import Candidate


_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>`]+")
_URI_USERINFO = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://(?P<user>[^\s/:@]+):(?P<password>[^\s/@]+)@"
)
_AUTH_HEADER = re.compile(
    r"(?im)\b(?P<header>(?:proxy-)?authorization|x-api-key|api-key|x-goog-api-key)[\"']?\s*[:=]\s*[\"']?\s*"
    r"(?:(?P<scheme>bearer|basic)\s+)?(?P<value>[^\s,;\"'<>]+)"
)
_COOKIE = re.compile(
    r"(?im)\b(?:set-cookie|cookie)\s*[:=]\s*[^\r\n;=\s]+="
    r"(?P<value>[^\r\n;\s,]+)"
)
_SIGNED_QUERY = re.compile(
    r"(?i)(?:[?&]|\b)(?:x-amz-signature|x-goog-signature|signature|sig|"
    r"access_token|auth_token|api[_-]?key|token|password|pwd)=(?P<value>[^&#\s\"'<>]*)"
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?:::[0-9A-Fa-f:]{0,})?(?![0-9A-Fa-f:.])"
)
_EMAIL = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![A-Z0-9_-])"
)
_PHONE = re.compile(r"(?<![\w])\+[1-9](?:[ .()-]*\d){7,14}(?!\w)")
_SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")
_HOME_PATH = re.compile(
    r"(?i)(?:/(?:Users|home)/[^/\s\"'<>:]+(?:/[^\s\"'<>]*)?|"
    r"[A-Z]:[\\/]Users[\\/][^\\/\s\"'<>:]+(?:[\\/][^\s\"'<>]*)?|"
    r"\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\s\"'<>]*)?)"
)
_LOCAL_PATH = re.compile(r"(?i)(?:/Volumes/[^/\s\"'<>]+|/private/var/(?:folders|tmp)/[^\s\"'<>]+)")
_RUNTIME_FIELDS = frozenset(normalize_key(key) for key in (
    "email", "phone", "mobile", "customer_id", "tenant_id", "session_id",
    "session_token", "device_id", "device_uuid", "udid", "ecid", "full_name",
    "billing_address", "address", "date_of_birth", "birth_date", "ssn",
    "national_id", "credit_card", "card_number", "ip_address",
))
_SIGNED_QUERY_FIELDS = frozenset({
    "x-amz-signature", "x-goog-signature", "signature", "sig", "access_token",
    "auth_token", "api-key", "api_key", "token",
})
_PRIVATE_HOST_LABELS = frozenset({
    "admin", "backend", "database", "db", "internal", "intranet", "private",
    "corp", "cluster", "staging", "stage", "production", "prod", "localhost",
})
_DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))
_PUBLIC_HOME_NAMES = frozenset({"shared", "public", "runner", "runneradmin", "actions"})


# Exact public documentation and provider authorities; never suffix matching.
_PUBLIC_AUTHORITIES = frozenset({
    'ai.google.dev',
    'anthropic.go',
    'api-docs.deepseek.com',
    'api-inference.huggingface.co',
    'api.anthropic.com',
    'api.cerebras.ai',
    'api.cohere.ai',
    'api.cohere.com',
    'api.deepseek.com',
    'api.fireworks.ai',
    'api.groq.com',
    'api.hunyuan.cloud.tencent.com',
    'api.kimi.com',
    'api.minimax.io',
    'api.minimaxi.com',
    'api.mistral.ai',
    'api.moonshot.ai',
    'api.moonshot.cn',
    'api.openai.com',
    'api.perplexity.ai',
    'api.replicate.com',
    'api.siliconflow.cn',
    'api.siliconflow.com',
    'api.together.ai',
    'api.together.xyz',
    'api.x.ai',
    'api.z.ai',
    'ark.cn-beijing.volces.com',
    'aws.go',
    'cloud.baidu.com',
    'cloud.tencent.com',
    'console.groq.com',
    'crates.io',
    'dashscope-intl.aliyuncs.com',
    'dashscope-us.aliyuncs.com',
    'dashscope.aliyuncs.com',
    'datatracker.ietf.org',
    'dev.mysql.com',
    'developer.hashicorp.com',
    'developers.openai.com',
    'docs.api.nvidia.com',
    'docs.aws.amazon.com',
    'docs.cohere.com',
    'docs.confluent.io',
    'docs.fireworks.ai',
    'docs.github.com',
    'docs.influxdata.com',
    'docs.mistral.ai',
    'docs.nats.io',
    'docs.opensearch.org',
    'docs.siliconflow.cn',
    'docs.slack.dev',
    'docs.together.ai',
    'docs.volcengine.com',
    'docs.x.ai',
    'gcp.go',
    'generativelanguage.googleapis.com',
    'github.com',
    'github.go',
    'help.aliyun.com',
    'huggingface.co',
    'huggingface.go',
    'inference-docs.cerebras.ai',
    'integrate.api.nvidia.com',
    'learn.microsoft.com',
    'mariadb.com',
    'neo4j.com',
    'open.bigmodel.cn',
    'openai.go',
    'openrouter.ai',
    'perplexity.go',
    'platform.claude.com',
    'platform.kimi.ai',
    'platform.minimax.io',
    'pub.dev',
    'qianfan.baidubce.com',
    'raw.githubusercontent.com',
    'redis.io',
    'registry.npmjs.org',
    'replicate.com',
    'router.huggingface.co',
    'sasl.jaas.config',
    'slack.go',
    'www.apache.org',
    'www.elastic.co',
    'www.mongodb.com',
    'www.postgresql.org',
    'www.rabbitmq.com',
    'www.rfc-editor.org',
    'www.w3.org',
})


def _policy(profile: Mapping[str, object]) -> Mapping[str, object]:
    value = profile.get("privacy_policy", {})
    return value if isinstance(value, Mapping) else {}


def _in_scope(path: str, path_globs: object) -> bool:
    if not isinstance(path_globs, (list, tuple)):
        return False
    repo_path = path.replace("\\", "/").removeprefix("./")
    return any(
        isinstance(pattern, str) and pattern and fnmatchcase(repo_path, pattern)
        for pattern in path_globs
    )


def _domain_is_allowed(host: str, scheme: str, path: str, profile: Mapping[str, object]) -> bool:
    entries = _policy(profile).get("privacy_domain_allowlist", ())
    if not isinstance(entries, (list, tuple)):
        return False
    host = host.casefold().rstrip(".")
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        allowed_host = entry.get("host")
        schemes = entry.get("schemes", ())
        if not isinstance(allowed_host, str) or allowed_host.casefold().rstrip(".") != host:
            continue
        if schemes and (not isinstance(schemes, (list, tuple)) or scheme.casefold() not in {item.casefold() for item in schemes if isinstance(item, str)}):
            continue
        if _in_scope(path, entry.get("path_globs", ())):
            return True
    return False


def _ip_is_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, path: str, profile: Mapping[str, object]) -> bool:
    entries = _policy(profile).get("privacy_ip_allowlist", ())
    if not isinstance(entries, (list, tuple)):
        return False
    for entry in entries:
        if not isinstance(entry, Mapping) or not _in_scope(path, entry.get("path_globs", ())):
            continue
        values = entry.get("ips", ())
        if not isinstance(values, (list, tuple)):
            continue
        for value in values:
            if not isinstance(value, str):
                continue
            try:
                if ipaddress.ip_address(value) == address:
                    return True
            except ValueError:
                continue
    return False


def _is_svg_path_data(text: str, start: int, path: str) -> bool:
    if not path.casefold().endswith(".svg"):
        return False
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    before = line[: start - line_start].casefold()
    return bool(re.search(r"<path\b[^>]*\bd\s*=\s*[\"'][^\"']*$", before))


def _network_candidates(text: str, path: str, profile: Mapping[str, object]) -> Iterator[Candidate]:
    seen: set[tuple[int, int]] = set()
    for pattern in (_IPV4, _IPV6):
        for match in pattern.finditer(text):
            span = match.span()
            if pattern is _IPV6 and path.endswith(".rs") and re.fullmatch(r"[A-Za-z]\w*::[A-Za-z]\w*", match.group()):
                before = text[max(0, span[0]-1):span[0]]
                after = text[span[1]:span[1]+1]
                if before not in {'"', "'", "["} and after not in {'"', "'", "]"}:
                    continue
            if span in seen or _is_svg_path_data(text, span[0], path):
                continue
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if address.is_loopback or address.is_unspecified:
                continue
            if any(address in network for network in _DOCUMENTATION_NETWORKS if address.version == network.version):
                continue
            if _ip_is_allowed(address, path, profile):
                continue
            seen.add(span)
            yield Candidate(*span, "IP address literal outside loopback and documentation ranges", (span,))


def _endpoint_candidates(text: str, path: str, profile: Mapping[str, object]) -> Iterator[Candidate]:
    for match in _URL.finditer(text):
        raw_url = match.group().rstrip(".,;:!?)}]")
        try:
            parsed = urlsplit(raw_url)
            host = parsed.hostname
        except ValueError:
            continue
        if not host:
            continue
        normalized = host.casefold().rstrip(".")
        public_reference = normalized in {"example.com", "example.org", "example.net", "localhost"} or normalized.endswith((".example", ".invalid", ".test", ".localhost", ".example.com", ".example.org", ".example.net"))
        try:
            address = ipaddress.ip_address(normalized)
            public_reference = public_reference or address.is_loopback or address.is_unspecified or any(address in network for network in _DOCUMENTATION_NETWORKS if address.version == network.version)
        except ValueError:
            pass
        if parsed.scheme.lower() not in {"http", "https", "ws", "wss", "ssh", "postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps", "nats"}:
            continue
        if public_reference or normalized in _PUBLIC_AUTHORITIES or _domain_is_allowed(host, parsed.scheme, path, profile):
            continue
        start, end = match.span()
        end -= len(match.group()) - len(raw_url)
        yield Candidate(start, end, "Parsed service endpoint; ownership and publication context require review", ((start, end),))


def _userinfo_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for match in _URI_USERINFO.finditer(text):
        start, end = match.span("password")
        value = match.group("password")
        decoded = unquote(value)
        if not is_placeholder(decoded) and not any(char in decoded for char in "<>$`{}"):
            yield Candidate(start, end, "URL authority contains literal authentication material", ((start, end),))


    for match in _URL.finditer(text):
        try:
            parsed = urlsplit(match.group())
        except ValueError:
            continue
        if parsed.scheme != "nats" or parsed.password is not None or not parsed.username:
            continue
        decoded = unquote(parsed.username)
        if is_placeholder(decoded) or any(char in decoded for char in "<>$`{}"):
            continue
        start = match.start() + len(parsed.scheme) + 3
        end = start + len(parsed.username)
        yield Candidate(start, end, "NATS URL authority contains a literal access token", ((start, end),))


def _auth_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for pattern in (_AUTH_HEADER, _COOKIE, _SIGNED_QUERY):
        for match in pattern.finditer(text):
            start, end = match.span("value")
            value = match.group("value").rstrip("&;,")
            end -= len(match.group("value")) - len(value)
            if pattern is _AUTH_HEADER:
                scheme = (match.group("scheme") or "").casefold()
                if scheme == "basic":
                    try:
                        decoded = base64.b64decode(value, validate=True).decode("utf-8")
                        user, delimiter, password = decoded.partition(":")
                        if not delimiter or is_placeholder(password):
                            continue
                    except (ValueError, UnicodeError, binascii.Error):
                        continue
                if not scheme and match.group("header").casefold().endswith("authorization"):
                    # Other authorization schemes retain the complete field value.
                    suffix = re.match(r"[^\r\n\"']*", text[end:])
                    if suffix:
                        end += len(suffix.group().rstrip())
                        value = text[start:end]
            if not is_placeholder(unquote(value)) and not any(char in unquote(value) for char in "<>$`{}"):
                yield Candidate(start, end, "Literal authentication header, cookie, or signed-query value", ((start, end),))


def _personal_field_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for key, value, start, end, _quoted in _binding_matches(text):
        if normalize_key(key) not in _RUNTIME_FIELDS or is_placeholder(value):
            continue
        yield Candidate(start, end, "Literal assigned to a user, device, session, or runtime-data field", ((start, end),))


def _simple_personal_candidates(pattern: re.Pattern[str], text: str, basis: str) -> Iterator[Candidate]:
    for match in pattern.finditer(text):
        span = match.span()
        yield Candidate(*span, basis, (span,))


def _personal_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    yield from _simple_personal_candidates(_EMAIL, text, "Email-address-shaped personal data")
    yield from _simple_personal_candidates(_PHONE, text, "International phone-number-shaped personal data")
    yield from _simple_personal_candidates(_SSN, text, "National-identifier-shaped personal data")
    for match in _CARD.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and _passes_luhn(digits):
            span = match.span()
            yield Candidate(*span, "Payment-card-shaped personal data with a valid Luhn checksum", (span,))


def _passes_luhn(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        value = ord(character) - ord("0")
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _local_path_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for pattern in (_HOME_PATH, _LOCAL_PATH):
        for match in pattern.finditer(text):
            candidate = match.group()
            normalized = candidate.replace("\\", "/").casefold()
            parts = normalized.split("/")
            home_index = next((index for index, part in enumerate(parts) if part in {"users", "home"}), None)
            if home_index is not None and home_index + 1 < len(parts) and any(char in parts[home_index + 1] for char in "$<>`{}"):
                continue
            span = match.span()
            yield Candidate(*span, "Machine-local account or volume path", (span,))


def context_rules():
    return (
        ("privacy.credential.uri-userinfo", "Credentials", "URL contains literal authentication material", _userinfo_candidates),
        ("privacy.credential.auth-header", "Credentials", "Authentication header, cookie, or signed query literal", _auth_candidates),
        ("privacy.endpoint.private-host", "Backend information", "Service endpoint whose publication context requires review", _endpoint_candidates),
        ("privacy.endpoint.ip-address", "Network information", "IP address literal requiring endpoint context review", _network_candidates),
        ("privacy.personal.record-field", "Runtime and personal data", "Literal user, device, session, or runtime-data field", _personal_field_candidates),
        ("privacy.personal.identifier", "Runtime and personal data", "Personal identifier-shaped value", _personal_candidates),
        ("privacy.business.assignment", "Runtime and personal data", "Literal commercial or business information field", _business_candidates),
        ("privacy.backend.metadata", "Backend information", "Literal backend or production metadata field", _backend_candidates),
        ("privacy.backend.resource-id", "Backend information", "Provider resource identifier in operational files", _resource_candidates),
        ("privacy.endpoint.host-binding", "Backend information", "Host configuration or SSH account endpoint", _host_candidates),
        ("privacy.local.deployment-path", "Local information", "Machine-specific deployment or workspace path", _deployment_candidates),
        ("privacy.local.machine-path", "Local information", "Machine-local account or volume path", _local_path_candidates),
    )


_BUSINESS_FIELDS = frozenset(normalize_key(key) for key in (
    "arr", "billing_account", "commercial_account", "contract_id", "customer",
    "customer_id", "customer_name", "deal", "deal_id", "invoice", "invoice_id",
    "lead", "licensee", "mrr", "partner", "prospect", "revenue", "sales_account",
))
_BACKEND_FIELDS = frozenset(normalize_key(key) for key in (
    "account_id", "bucket", "bucket_name", "cluster", "cluster_name", "container_image",
    "database", "database_name", "datacenter", "db_name", "droplet_id", "image",
    "instance", "instance_id", "kube_context", "namespace", "project_id", "region",
    "registry", "resource_group", "server_id", "service_name", "subscription_id",
    "tenant_id", "zone", "hostname", "label",
))
_HOST_FIELDS = frozenset(normalize_key(key) for key in (
    "host", "hostname", "domain", "endpoint", "url", "origin", "server", "baseUrl", "apiUrl", "remote",
))
_HOST_LITERAL = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*")
_SSH_ACCESS = re.compile(r"(?<![\w.-])[A-Za-z0-9._-]+@(?P<host>(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+):[0-9]{1,5}\b")
_RESOURCE_ID = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")
_DEPLOYMENT_PATH = re.compile(r"(?i)(?<![A-Za-z0-9_.:])(?:/(?:private/)?var/folders/|/(?:Volumes|etc|tmp|opt|root|srv|usr/local|var/lib|var/log|var/run|private/tmp)/)[^\s`'\"),;<>]+")
_WINDOWS_WORKSPACE = re.compile(r"(?i)(?<![A-Za-z0-9_.-])[A-Z]:[\\/](?:[^\\/\s`'\"<>]+[\\/])?(?:dev(?:elopment|space)?|projects?|repos(?:itories)?|workspaces?)[\\/][^\s`'\"<>]+")
_PUBLIC_SYSTEM_PREFIXES = (
    "/opt/homebrew", "/opt/local", "/usr/local/bin", "/usr/local/lib",
    "/usr/local/sbin", "/usr/local/share", "/etc/ssh", "/etc/ssl",
    "/root/.pub-cache", "/root/.cargo/registry", "/root/.cargo/git",
)


def _metadata_candidates(text, path, profile, *, fields, basis):
    for key, value, start, end, quoted in _binding_matches(text):
        if normalize_key(key) not in fields or is_placeholder(value):
            continue
        if not quoted and re.fullmatch(r"[A-Za-z_]\w*(?:(?:\.|::)[A-Za-z_]\w*)+", value):
            continue
        yield Candidate(start, end, basis, ((start, end),))


def _business_candidates(text, path, profile):
    yield from _metadata_candidates(text, path, profile, fields=_BUSINESS_FIELDS, basis="Literal business or commercial record field requiring provenance review")


def _backend_candidates(text, path, profile):
    yield from _metadata_candidates(text, path, profile, fields=_BACKEND_FIELDS, basis="Literal backend, provider, or deployment metadata field")


def _host_candidates(text, path, profile):
    for key, value, start, end, _quoted in _binding_matches(text):
        if normalize_key(key) not in _HOST_FIELDS or not _HOST_LITERAL.fullmatch(value):
            continue
        synthetic = "https://" + value
        if next(_endpoint_candidates(synthetic, path, profile), None) is not None:
            yield Candidate(start, end, "Host or domain configuration literal requiring ownership review", ((start, end),))
    for match in _SSH_ACCESS.finditer(text):
        if next(_endpoint_candidates("ssh://" + match.group("host"), path, profile), None) is not None:
            yield Candidate(*match.span(), "SSH account and remote endpoint access metadata", (match.span(),))


def _resource_candidates(text, path, _profile):
    normalized = path.replace("\\", "/").lower()
    if not (normalized.startswith(("deployment/", "deploy/", "ops/", "infrastructure/", "terraform/")) or normalized.endswith("vultr-ip-finder.ps1")):
        return
    for match in _RESOURCE_ID.finditer(text):
        yield Candidate(*match.span(), "Provider resource identifier in operational material", (match.span(),))


def _deployment_candidates(text, path, _profile):
    for pattern in (_DEPLOYMENT_PATH, _WINDOWS_WORKSPACE):
        for match in pattern.finditer(text):
            value = match.group().replace("\\", "/").rstrip("/").lower()
            if value in {"/etc/hosts", "/etc/passwd", "/etc/resolv.conf"}:
                continue
            if any(value == prefix or value.startswith(prefix + "/") for prefix in _PUBLIC_SYSTEM_PREFIXES):
                continue
            if any(value == root or value.startswith(root + "/") for root in ("/tmp/example", "/tmp/synthetic-fixture-root", "/private/tmp/example", "/private/tmp/synthetic-fixture-root")):
                continue
            if any(character in value for character in "${}<>"):
                continue
            yield Candidate(*match.span(), "Machine-specific deployment, temporary, volume, or workspace path", (match.span(),))
