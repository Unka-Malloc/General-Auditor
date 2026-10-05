"""Portable provider credential field and token-format signals."""

from collections.abc import Iterator, Mapping
import re

from .types import Candidate


# Public field identifiers are matched case-insensitively after punctuation
# normalization. They are policy signals, not evidence that a value is live.
PROVIDER_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("openai", ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY")),
    ("anthropic", ("ANTHROPIC_API_KEY", "ANTHROPIC_ADMIN_KEY")),
    ("google-gemini", ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    ("deepseek", ("DEEPSEEK_API_KEY",)),
    ("moonshot", ("MOONSHOT_API_KEY", "KIMI_API_KEY")),
    ("zhipu", ("ZHIPUAI_API_KEY", "ZAI_API_KEY")),
    ("minimax", ("MINIMAX_API_KEY",)),
    ("dashscope", ("DASHSCOPE_API_KEY",)),
    ("qianfan", ("QIANFAN_API_KEY", "QIANFAN_SECRET_KEY")),
    ("volcengine-ark", ("ARK_API_KEY",)),
    ("siliconflow", ("SILICONFLOW_API_KEY",)),
    ("xai", ("XAI_API_KEY",)),
    ("mistral", ("MISTRAL_API_KEY",)),
    ("cohere", ("CO_API_KEY", "COHERE_API_KEY")),
    ("groq", ("GROQ_API_KEY",)),
    ("together", ("TOGETHER_API_KEY",)),
    ("fireworks", ("FIREWORKS_API_KEY",)),
    ("openrouter", ("OPENROUTER_API_KEY",)),
    ("huggingface", ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_API_KEY")),
    ("replicate", ("REPLICATE_API_TOKEN",)),
    ("perplexity", ("PERPLEXITY_API_KEY",)),
    ("hunyuan", ("HUNYUAN_API_KEY",)),
    ("cerebras", ("CEREBRAS_API_KEY",)),
    ("nvidia", ("NGC_API_KEY", "NVIDIA_API_KEY")),
    ("postgresql", ("PGPASSWORD", "POSTGRES_PASSWORD")),
    ("mysql", ("MYSQL_PWD", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD")),
    ("mariadb", ("MARIADB_PASSWORD", "MARIADB_ROOT_PASSWORD")),
    ("mongodb", ("MONGO_INITDB_ROOT_PASSWORD", "MONGODB_PASSWORD")),
    ("redis", ("REDISCLI_AUTH", "REDIS_PASSWORD")),
    ("rabbitmq", ("RABBITMQ_DEFAULT_PASS",)),
    ("kafka", ("KAFKA_SASL_JAAS_CONFIG", "sasl.jaas.config")),
    ("nats", ("NATS_TOKEN", "NATS_PASSWORD")),
    ("elasticsearch", ("ELASTIC_PASSWORD", "ELASTIC_API_KEY")),
    ("opensearch", ("OPENSEARCH_INITIAL_ADMIN_PASSWORD",)),
    ("clickhouse", ("CLICKHOUSE_PASSWORD",)),
    ("sqlserver", ("MSSQL_SA_PASSWORD",)),
    ("oracle", ("ORACLE_PWD",)),
    ("neo4j", ("NEO4J_AUTH",)),
    ("influxdb", ("INFLUX_TOKEN", "DOCKER_INFLUXDB_INIT_ADMIN_TOKEN", "DOCKER_INFLUXDB_INIT_PASSWORD")),
    ("vault", ("VAULT_TOKEN",)),
    ("consul", ("CONSUL_HTTP_TOKEN",)),
    ("minio", ("MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY")),
    ("etcd", ("ETCDCTL_PASSWORD",)),
    ("couchdb", ("COUCHDB_PASSWORD",)),
    ("aws-secret", ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")),
    ("aws-key-id", ("AWS_ACCESS_KEY_ID",)),
    ("azure-openai", ("AZURE_OPENAI_API_KEY",)),
    ("aws-bedrock", ("AWS_BEARER_TOKEN_BEDROCK",)),
    ("github", ("GITHUB_TOKEN", "GH_TOKEN")),
    ("slack", ("SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN")),
)


def normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


FAMILY_BY_KEY = {
    normalize_key(field): family
    for family, fields in PROVIDER_FIELDS
    for field in fields
}

GENERIC_FIELDS = frozenset(
    normalize_key(key)
    for key in (
        "api_key", "api-key", "access_token", "auth_token", "refresh_token",
        "client_secret", "secret_key", "private_key", "password", "passwd",
        "pwd", "token", "bearer_token", "authorization", "proxy_authorization",
        "credential", "credentials", "secret", "signing_key", "consumer_key",
        "consumer_secret", "webhook_secret", "session_token", "session_key",
        "cookie", "set_cookie", "secret_access_key", "access_key_id",
        "database_url", "connection_string",
    )
)

_QUOTED_BINDING = re.compile(
    r"(?<![\w.-])(?P<key>[\"'](?:\\.|[^\"'\\])*[\"']|[A-Za-z_][A-Za-z0-9_.-]*)"
    r"\s*(?::|=|:=)\s*(?P<quote>[\"'])"
    r"(?P<value>(?:\\.|[^\"'\\])*)?(?P=quote)",
    re.MULTILINE,
)
_UNQUOTED_BINDING = re.compile(
    r"(?<![\w.-])(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*(?::|=|:=)\s*"
    r"(?P<value>[^\s,;#}\]]+)",
    re.MULTILINE,
)
_REFERENCE = re.compile(
    r"(?i)^(?:\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|"
    r"env:[A-Z_][A-Z0-9_]*|\$env:[A-Z_][A-Z0-9_]*|"
    r"process\.env(?:\.[A-Z_][A-Z0-9_]*)?|"
    r"import\.meta\.env(?:\.[A-Z_][A-Z0-9_]*)?|"
    r"os\.environ(?:\[[^]]+\]|\.[A-Z_][A-Z0-9_]*)?|"
    r"(?:current|this|self|settings|config|secrets|vars)\.[A-Za-z_][A-Za-z0-9_.]*|"
    r"(?:os\.(?:getenv|environ)|System\.getenv|std::env|env\(|getenv\().*|"
    r"\{\{[^}]+\}\}|%[A-Z_][A-Z0-9_]*%)$"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:<[^<>\r\n]{1,80}>|\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|"
    r"your[-_][A-Za-z0-9_-]+|replace[-_](?:me|this)|redacted|"
    r"changeme|change[-_]?me|not[-_]?a[-_]?secret|"
    r"(?:x{3,}|\*{3,}|[-_]{3,})|(?:example|placeholder|dummy)[_-](?:[a-z_-]*)(?:key|token|password|secret|here))$"
)
_IDENTIFIER_REFERENCE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")


def is_placeholder(value: str) -> bool:
    candidate = value.strip()
    return not candidate or bool(_PLACEHOLDER.fullmatch(candidate)) or bool(_REFERENCE.fullmatch(candidate))


def is_secret_field(key: str) -> bool:
    normalized = normalize_key(key.strip().strip("\"'"))
    if normalized in GENERIC_FIELDS or normalized in FAMILY_BY_KEY:
        return True
    return normalized.endswith((
        "apikey", "accesstoken", "authtoken", "refreshtoken", "clientsecret",
        "secretkey", "privatekey", "password", "passwd", "token", "secret",
        "credential", "credentials", "signingkey", "webhooksecret",
    ))


def _binding_matches(text: str) -> Iterator[tuple[str, str, int, int, bool]]:
    seen: set[tuple[int, int]] = set()
    for pattern, quoted in ((_QUOTED_BINDING, True), (_UNQUOTED_BINDING, False)):
        for match in pattern.finditer(text):
            start, end = match.span("value")
            if (start, end) in seen:
                continue
            seen.add((start, end))
            raw_key = match.group("key").strip().strip("\"'")
            value = match.group("value") or ""
            if not quoted and value.startswith(("\"", "'")):
                continue
            yield raw_key, value, start, end, quoted


def _field_candidates(text: str, family: str) -> Iterator[Candidate]:
    for key, value, start, end, quoted in _binding_matches(text):
        if FAMILY_BY_KEY.get(normalize_key(key)) != family or is_placeholder(value):
            continue
        if not quoted and _IDENTIFIER_REFERENCE.fullmatch(value.strip()):
            continue
        yield Candidate(start, end, "Literal assignment to a provider credential field", ((start, end),))


def family_finder(family: str):
    def find(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
        yield from _field_candidates(text, family)

    return find


def generic_binding_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for key, value, start, end, quoted in _binding_matches(text):
        normalized = normalize_key(key)
        if normalized == "authorization" and value.casefold() in {"bearer", "basic"}:
            continue
        if normalized in FAMILY_BY_KEY or not is_secret_field(key) or is_placeholder(value):
            continue
        if not quoted and _IDENTIFIER_REFERENCE.fullmatch(value.strip()):
            continue
        yield Candidate(start, end, "Literal assignment to a credential or authentication field", ((start, end),))


_TOKEN_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("openai", "OpenAI token format", r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}T3BlbkFJ[A-Za-z0-9_-]{40,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b"),
    ("anthropic", "Anthropic token format", r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA\b"),
    ("google-gemini", "Google API token format", r"\bAIza[A-Za-z0-9_-]{35}\b"),
    ("xai", "xAI token format", r"\bxai-[A-Za-z0-9_]{80}\b"),
    ("groq", "Groq token format", r"\bgsk_[A-Za-z0-9]{52}\b"),
    ("openrouter", "OpenRouter token format", r"\bsk-or-v1-[0-9a-f]{64}\b"),
    ("huggingface", "Hugging Face token format", r"\b(?:hf_|api_org_)[A-Za-z]{34}\b"),
    ("replicate", "Replicate token format", r"\br8_[A-Za-z0-9]{37}\b"),
    ("perplexity", "Perplexity token format", r"\bpplx-[A-Za-z0-9]{48}\b"),
    ("aws-key-id", "AWS access-key identifier format", r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b"),
    ("aws-bedrock", "AWS Bedrock token format", r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}\b"),
    ("github", "GitHub token format", r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
    ("slack", "Slack token format", r"\b(?:xoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*|xoxp-(?:[0-9]{10,13}-){3}[A-Za-z0-9-]{28,34}|xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)\b"),
    ("candidate-prefix", "Credential-shaped token requiring contextual review", r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9_]{30,}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
    ("stripe", "Stripe API token format", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
)


def provider_rules():
    """Return the static provider-family and format rules with source-free finders."""
    families = tuple(
        (f"privacy.credential.provider.{family}", "Credentials",
         f"Literal binding to a {family} credential field", family_finder(family))
        for family, _fields in PROVIDER_FIELDS
    )
    tokens = tuple(
        (f"privacy.credential.format.{family}", "Credentials", description,
         token_format_finder(family))
        for family, description, _pattern in _TOKEN_SIGNATURES
    )
    return families + (
        ("privacy.credential.binding", "Credentials",
         "Literal binding to a generic credential or authentication field", generic_binding_candidates),
    ) + tokens


def token_format_finder(rule_id: str):
    _, _, pattern = next(item for item in _TOKEN_SIGNATURES if item[0] == rule_id)
    compiled = re.compile(pattern)

    def find(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
        for match in compiled.finditer(text):
            yield Candidate(*match.span(), "Recognized provider token shape; validity is not tested", (match.span(),))

    return find


_TOKEN_RULES = tuple(
    (f"privacy.credential.format.{family}", description, pattern)
    for family, description, pattern in _TOKEN_SIGNATURES
)
_TOKEN_COMBINED = re.compile("|".join(
    f"(?P<TOKEN_{index}>{pattern})"
    for index, (_rule_id, _description, pattern) in enumerate(_TOKEN_RULES)
))


def collect_provider_candidates(text: str) -> dict[str, list[Candidate]]:
    """Index provider field and token-shape matches in linear text passes."""
    found: dict[str, list[Candidate]] = {}
    for key, value, start, end, quoted in _binding_matches(text):
        family = FAMILY_BY_KEY.get(normalize_key(key))
        if normalize_key(key) == "authorization" and value.casefold() in {"bearer", "basic"}:
            continue
        if family and not is_placeholder(value) and (quoted or not _IDENTIFIER_REFERENCE.fullmatch(value.strip())):
            rule = f"privacy.credential.provider.{family}"
            found.setdefault(rule, []).append(Candidate(
                start, end, "Literal assignment to a provider credential field", ((start, end),)
            ))
        if (family is None and is_secret_field(key) and not is_placeholder(value)
                and (quoted or not _IDENTIFIER_REFERENCE.fullmatch(value.strip()))):
            found.setdefault("privacy.credential.binding", []).append(Candidate(
                start, end, "Literal assignment to a credential or authentication field", ((start, end),)
            ))
    for match in _TOKEN_COMBINED.finditer(text):
        group = match.lastgroup
        if group is None:
            continue
        index = int(group.removeprefix("TOKEN_"))
        rule_id = _TOKEN_RULES[index][0]
        found.setdefault(rule_id, []).append(Candidate(
            *match.span(), "Recognized provider token shape; validity is not tested", (match.span(),)
        ))
    return found
