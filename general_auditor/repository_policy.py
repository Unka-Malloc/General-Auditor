"""Trusted, repository-scoped structural policy evaluation.

The evaluator consumes an immutable candidate tree and a centrally selected
profile. It never loads policy from the candidate, executes target code, or
returns target text. Pattern hits are warnings; applicable structural contract
failures are errors. This module intentionally uses only the standard library.
"""

from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from urllib.parse import unquote
import ipaddress
import json
import re

from .detection.paths import redact_path


POLICY_FIELDS = {
    "require_workflow", "data_profile", "documentation_profile", "hygiene_profile",
    "branch", "license", "dependencies", "project_inventory", "resource_contracts",
    "ci_contract", "server_boundary", "defect_records", "json_admissions", "schema_fixtures",
}
DATA_PROFILES = {"common", "website", "licoup", "badtower", "licoarc"}
DOCUMENTATION_PROFILES = {"lico-project", "licoup"}
HYGIENE_PROFILES = {"styio-default"}

COMMON_JSON_PATTERNS = (
    r"tools/release/source-version\.json",
    r"workflow-templates/[a-z0-9][a-z0-9._-]*\.properties\.json",
    r"github/rulesets/[^/]+\.json",
    r"(?:.*/)?tsconfig\.[a-z0-9_.-]+\.json",
    r"(?:.*/)?\.?mcp\.json",
    r"(?:.*/)?\.?codex-plugin/plugin\.json",
    r"(?:.*/)?\.?agents/plugins/marketplace\.json",
)
LICOUP_JSON_PATTERNS = (
    r'apps/desktop/assets/agent-render-adapters/[^/]+\.json',
    r'apps/desktop/assets/appearance-presets/[^/]+\.json',
    r'apps/desktop/ios/runner/assets\.xcassets/.+/contents\.json',
    r'apps/desktop/macos/runner/assets\.xcassets/.+/contents\.json',
    r'apps/desktop/macos/runner/assets\.xcassets/.+/sourcemanifest\.json',
    r'apps/desktop/packaging\.modules\.json',
    r'apps/desktop/test/(?:fixtures|layout)/.+\.json',
    r'crates/(?:lico-client-native|licoup-native)/resources/.+\.json',
    r'crates/licoup-native/src/domain/agent_intelligence_catalog/[^/]+\.json',
    r'crates/licoup-native/src/domain/provider_model_pricing/pricing_(?:catalog|snapshot)\.json',
    r'crates/(?:lico-client-native|licoup-native)/src/domain/targets/model_catalog/[^/]+\.json',
    r'packages/contracts/client/.+\.schema\.json',
    r'packages/contracts/client/fixtures/.+\.json',
    r'schemas/client_bridge/[^/]+\.json',
    r'schemas/conversation_protocol/[^/]+\.json',
    r'tools/android-release-toolchain\.json',
    r'tools/apple-release/[^/]+\.json',
    r'tools/client-[^/]+\.json',
    r'tools/scripts/[^/]+/probes\.json',
)
LICOUP_EXACT_JSON_PATHS = frozenset({
    'tools/scripts/config/client-artifact-verification-receipts-report.schema.json',
    'tools/scripts/config/client-artifact-verification-receipts.json',
    'tools/scripts/config/client-release-acceptance-report.schema.json',
    'tools/scripts/config/client-release-acceptance.json',
    'tools/scripts/config/readme-fast-files.json',
    'tools/scripts/config/secure-mesh-acp-archive-release-proof.json',
    'tools/scripts/config/secure-mesh-acp-relay-governed-baseline.json',
    'tools/scripts/config/secure-mesh-client-boundary.json',
    'tools/scripts/config/secure-mesh-e2ee-evidence-routes.json',
    'tools/scripts/config/secure-mesh-e2ee-report-scope.json',
    'tools/scripts/config/secure-mesh-encrypted-file-handoff.json',
    'tools/scripts/config/secure-mesh-pairwise-content-audit.json',
    'tools/scripts/config/secure-mesh-pairwise-review-authorities.json',
    'tools/scripts/config/secure-mesh-physical-device-matrix.json',
    'tools/scripts/config/secure-mesh-physical-evidence.json',
    'tools/scripts/config/secure-mesh-platform-secret-store-matrix.json',
    'tools/scripts/config/secure-mesh-release-proof.json',
    'tools/scripts/config/secure-mesh-report-redaction.json',
    'tools/scripts/config/secure-mesh-trust-ux.json',
    'tools/scripts/config/secure-mesh-windows-implementation.json',
})
LICOUP_JSON_LIST_PATHS = frozenset({
    'tools/development/state-machines.json',
    'tools/scripts/config/readme-fast-files.json',
})
LICOUP_SYNTHETIC_DATA_PATTERNS = (
)
BADTOWER_JSON_PATTERNS = (
    r"docs/examples/[^/]+(?:\.template|\.schema)?\.json",
    r"config/[^/]+(?:\.template|\.schema)?\.json",
    r"schemas/.+\.json", r"registry/(?:core-host-contract|plugins)\.json", r"vendor/[^/]+\.json",
)
LICOARC_JSON_PATTERNS = (
    r"artifacts/[^/]+\.json", r"conformance/.+\.json", r"contracts/.+\.json",
    r"docs/examples/[^/]+(?:\.template|\.schema)?\.json", r"policies/.+\.json",
    r"protocols/(?:generated|schemas)/.+\.json", r"registry/.+\.json", r"schemas/.+\.json",
)
COMMON_JSON_NAMES = {"package.json", "package-lock.json", "tsconfig.json"}
JSON_MARKERS = {
    "$id", "$schema", "bundleType", "capabilities", "compression", "compilerOptions",
    "contextWindowTokens", "defaultForAgents", "defaults", "dependencies", "description",
    "darkPresetId", "displayName", "downloads", "entries", "entityType", "events", "files",
    "frameworks", "grantable", "historyBudget", "id", "images", "info", "initialState",
    "items", "javaBinPath", "kind", "label", "lightPresetId", "manifest", "machines",
    "machineId", "maxRisk", "modelAlias", "module_id", "module_type", "name", "operations",
    "packages", "profiles", "profileId", "provider", "protocolVersion", "openapi", "properties",
    "requiredScopes", "routes", "schema", "schemaVersion", "scripts", "selectionPolicy",
    "serverUrl", "serviceId", "serviceName", "states", "strategies", "strategy", "targets",
    "templates", "tikaJarPath", "toolsets", "target_repositories", "type", "validation", "version",
    "waitServer",
}
BINARY_DATA_SUFFIXES = {
    ".arrow", ".avro", ".db", ".feather", ".orc", ".parquet", ".sqlite", ".sqlite3", ".xls", ".xlsx",
}
DATA_DUMP_SUFFIXES = {".csv", ".tsv", ".sql", ".dump", ".jsonl", ".ndjson"}

STYIO_FORBIDDEN_NAMES = {
    ".DS_Store", "Thumbs.db", "Desktop.ini", ".coverage", "coverage.xml",
    "flutter_export_environment.sh", "generated_plugin_registrant.cc", "generated_plugin_registrant.h",
    "generated_plugins.cmake", ".flutter-plugins", ".flutter-plugins-dependencies", "local.properties",
}
STYIO_FORBIDDEN_PARTS = {
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", "__pycache__", ".dart_tool",
    "node_modules", "build", "dist", "out", "DerivedData",
}
STYIO_FORBIDDEN_SUFFIXES = (
    "~", ".tmp", ".temp", ".bak", ".orig", ".rej", ".swp", ".swo", ".log", ".sqlite", ".sqlite3",
    ".db", ".db-journal", ".parquet", ".arrow", ".npy", ".npz", ".pkl", ".pickle", ".dump", ".dmp",
    ".profraw", ".profdata", ".gcda", ".gcno", ".zip", ".tar", ".tgz", ".tar.gz", ".7z", ".rar",
)

LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md", "COPYING.txt")
LICENSE_METADATA_FILES = ("pyproject.toml", "package.json", "pubspec.yaml")
LICENSE_NOTICE_FILES = (
    "LICENSE-POLICY.md", "NOTICE", "NOTICE.md", "README.md", "docs/LICENSE-POLICY.md",
)
DEPENDENCY_GLOBS = (
    "package.json", "**/package.json", "pyproject.toml", "**/pyproject.toml", "pubspec.yaml",
    "**/pubspec.yaml", "CMakeLists.txt", "**/CMakeLists.txt", "requirements*.txt", "**/requirements*.txt",
    "Cargo.toml", "**/Cargo.toml", "go.mod", "**/go.mod", "Package.swift", "**/Package.swift",
    "vcpkg.json", "**/vcpkg.json",
)
DEPENDENCY_BOUNDARY_FILES = (
    "DEPENDENCY-USAGE.md", "THIRD-PARTY-NOTICES.md", "docs/DEPENDENCY-USAGE.md", "docs/dependencies.md",
    "docs/third-party.md", "docs/specs/DEPENDENCY-USAGE.md", "docs/specs/dependencies.md", "docs/specs/third-party.md",
)
DEPENDENCY_MARKER_GROUPS = (
    "dependency|依赖", "commercial|商业", "authorization|授权", "usage boundary|使用边界|边界",
)
COMMERCIAL_TERMS = (
    "commercial license", "commercial authorization", "paid license", "subscription", "membership",
    "member-only", "trial license", "evaluation only", "proprietary", "商业授权", "商业许可证",
    "付费授权", "订阅", "会员制", "试用授权", "专有许可证",
)

SERVER_RESTRICTED_GLOBS = (
    ".env", ".env.*", "**/.env", "**/.env.*", "**/.kube/**", "**/*kubeconfig*", "**/*.tfstate",
    "**/*.tfstate.*", "**/*.tfvars", "**/ansible/**", "**/deploy/prod/**", "**/deploy/production/**",
    "**/infra/**", "**/inventory.ini", "**/ops/**", "**/private/**", "**/prod/**", "**/production/**",
    "**/*.p12", "**/*.pfx", "**/id_rsa", "**/id_ed25519", "**/private/*.key", "**/private/*.pem",
    "**/production/*.key", "**/production/*.pem", "**/*prod*secret*.json", "**/*production*secret*.json",
)
SERVER_ALLOWED_NAME_MARKERS = ("example", "sample", "template", "test", "fixture", "fake", "dummy", "placeholder", "public")
SERVER_DANGEROUS_MARKERS = {
    "auth-bypass": ("allow_anonymous=true", "allow_anonymous = true", "skip_auth=true", "skip_auth = true", "auth_disabled=true", "auth_disabled = true", "disable_auth=true", "disable_auth = true"),
    "command-injection": ("shell=true", "shell = true", "os.system("),
    "custom-cryptography": ("custom crypto", "custom cryptography", "homegrown crypto", "roll your own crypto", "proprietary cipher", "xor cipher"),
    "csrf-disabled": ("csrf=false", "csrf = false", "csrf_disabled=true", "csrf_disabled = true", "csrf_exempt", "disable_csrf=true", "disable_csrf = true"),
    "cors-wildcard": ("access-control-allow-origin: *", "allow_origins=['*']", 'allow_origins=["*"]'),
    "jwt-none": ('"alg":"none"', '"alg": "none"', "'alg':'none'", "'alg': 'none'", "alg=none", "algorithm none"),
    "disabled-verification": ("verify_signature=false", "verify_signature = false", '"verify_signature": false', "rejectunauthorized: false", "ssl_verify=false", "tls_verify=false", "--no-check-certificate"),
    "default-credential": ("admin:admin", "password=password", "password = password", "default_password", "default_admin_password"),
    "debug-public-exposure": ("app.run(debug=true", "app.run(debug = true", "flask_debug=1", "django_debug=true"),
    "insecure-cookie": ("httponly=false", "http_only=false", "secure=false", "cookie_secure=false"),
    "insecure-random-secret": ("random.random secret", "random.random token", "random.random password", "math.random secret", "math.random token", "math.random password"),
    "rate-limit-disabled": ("rate_limit=false", "rate_limit = false", "rate_limit=0", "disable_rate_limit=true"),
    "ssrf-unrestricted-fetch": ("requests.get(url", "requests.post(url", "requests.put(url", "requests.delete(url", "urllib.request.urlopen(url", "fetch(url"),
    "weak-password-hash": ("hashlib.md5(password", "hashlib.sha1(password", "md5 password", "sha1 password", "password md5", "password sha1"),
    "plaintext-password-storage": ("plain text password", "plaintext password", "cleartext password", "store password as plain text", "store passwords as plain text", "password stored in plain text"),
}
SERVER_SCAN_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".py", ".sh", ".bash", ".yml", ".yaml", ".dart", ".js", ".ts", ".go", ".rs", ".java", ".kt", ".swift", ".md", ".toml", ".txt"}
BACKEND_MANIFEST_MARKERS = (
    "auth|authentication|authorization|identity|鉴权", "privacy|pii|personal data|隐私", "password|密码",
    "secret|token|key|credential|密钥", "production|offline|private material|not committed|不进仓库|离线",
    "permission matrix|route authorization|rbac|role based access|权限矩阵", "deployment security|deployment config|tls|cors|csrf|cookie|部署安全",
    "sbom|cve|dependency vulnerability|vulnerability scan|依赖漏洞", "dast|black-box|penetration|security regression|渗透",
    "runtime secret|secret manager|kms|key rotation|密钥轮换", "rate limit|anti replay|replay protection|nonce|idempotency|限流|重放",
    "log redaction|sensitive log|audit log|日志脱敏", "ssrf|egress allowlist|url allowlist|outbound request|出站",
    "command execution|shell injection|subprocess allowlist|命令执行",
)

LICO_REQUIRED_PATHS = (
    "README.md", "README.zh-CN.md", "PRODUCT.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
    "LICENSE", "SECURITY.md", "docs/README.md", "docs/RUNBOOK.md", "docs/COMPATIBILITY.md",
    "docs/ENTITY-CONFIG-LAYOUT.md", "docs/adrs/README.md",
)
LICO_REQUIRED_SECTIONS = ("docs/architecture/", "docs/functionality/", "docs/protocols/", "docs/examples/")
LICO_FORMAL_PREFIXES = ("docs/architecture/", "docs/functionality/", "docs/protocols/", "docs/examples/", "docs/adrs/")
LICO_FORMAL_FILES = {
    "docs/README.md", "docs/RUNBOOK.md", "docs/COMPATIBILITY.md", "docs/ENTITY-CONFIG-LAYOUT.md", "docs/STATUS.md",
}
LICOUP_FORMAL_PREFIXES = ("docs/modules/", "docs/platforms/", "docs/releases/")
LICOUP_FORMAL_FILES = {"docs/CLOSURE.md", "docs/RELEASE-PACKAGES.md", "docs/RELEASE-PACKAGES.zh-CN.md"}
LICO_LOCAL_PREFIXES = ("docs/plans/", "docs/reports/", "cache/", "build/")
LICO_IGNORE_SENTINELS = (
    "docs/plans/.lico-auditor-sentinel", "docs/reports/.lico-auditor-sentinel", "cache/.lico-auditor-sentinel", "build/.lico-auditor-sentinel",
)
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
EXTERNAL_LINK = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)
GENERATED_MARKER = re.compile(r"(?:<!--\s*generated(?:\s+projection)?\s*-->|^generated\s*:\s*(?:true|yes)\s*$)", re.I | re.M)
GENERATED_SOURCE = re.compile(r"(?:generated from|projection source|生成来源)", re.I)
GENERATED_UPDATE = re.compile(r"(?:regenerate|update (?:command|process)|更新方式|重新生成)", re.I)
CURSOR_IDENTITY = re.compile(r"(?i)(?<![a-z0-9])cursor(?:ai|bot|agent|[\s_.-]+(?:ai|bot|agent))?(?![a-z0-9])")
CONTRIBUTOR_FIELD = re.compile(r"(?i)\b(?:authors?|contributors?|maintainers?|developers?|credits?)\b\s*[\"']?\s*[:=]")
CONTRIBUTOR_HEADING = re.compile(r"(?im)^#{1,6}\s+(?:authors?|contributors?|maintainers?|credits?)\s*$")
COMMIT_TRAILER = re.compile(r"(?im)^(?:co-authored-by|signed-off-by|authored-by|committed-by|generated-by|assisted-by|made-with)\s*:[^\r\n]*")


def _safe_relative(path):
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        return False
    parts = PurePosixPath(path).parts
    return all(part not in {"", ".", ".."} for part in parts)


def _string_list(value, *, path_values=False):
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() and (not path_values or _safe_relative(item)) for item in value)


def _validate_resource_contracts(value):
    if not isinstance(value, list):
        raise ValueError("Repository resource contracts must be a list")
    seen = set()
    required_strings = ("id", "owner", "description", "copying_policy", "concurrency_policy", "nullability_policy", "cleanup_policy")
    for resource in value:
        if not isinstance(resource, dict) or any(not isinstance(resource.get(key), str) or not resource[key].strip() for key in required_strings):
            raise ValueError("Invalid repository resource contract")
        if resource["id"] in seen:
            raise ValueError("Duplicate repository resource contract id")
        seen.add(resource["id"])
        for key in ("scope_globs", "required_tests", "required_gates", "audit_risks"):
            if not _string_list(resource.get(key), path_values=(key == "scope_globs")):
                raise ValueError("Invalid repository resource contract list")
        machine = resource.get("state_machine")
        if not isinstance(machine, dict) or not isinstance(machine.get("source"), str) or not machine["source"].strip():
            raise ValueError("Invalid resource state machine")
        states = machine.get("states")
        transitions = machine.get("transitions")
        if not _string_list(states) or not states or len(set(states)) != len(states) or not isinstance(transitions, list) or not transitions:
            raise ValueError("Invalid resource state machine transitions")
        for transition in transitions:
            if (not isinstance(transition, dict) or transition.get("from") not in states or transition.get("to") not in states
                    or not isinstance(transition.get("on"), str) or not transition["on"].strip()):
                raise ValueError("Invalid resource state transition")
        if not _string_list(machine.get("invalid_operations")):
            raise ValueError("Invalid resource state-machine exclusions")


def _validate_ci_contract(contract):
    if not isinstance(contract, dict):
        raise ValueError("CI gate contract must be an object")
    def string_map(value):
        return isinstance(value, dict) and all(isinstance(k, str) and k.strip() and isinstance(v, str) and v.strip() for k, v in value.items())
    if "platform_adaptation" in contract and not string_map(contract["platform_adaptation"]):
        raise ValueError("Invalid CI platform adaptation map")
    if "test_gates" in contract and not string_map(contract["test_gates"]):
        raise ValueError("Invalid CI test gate map")
    if "classified_gates" in contract and not _string_list(contract["classified_gates"]):
        raise ValueError("Invalid CI classified gates")
    if "submit_readiness" in contract and (not isinstance(contract["submit_readiness"], str) or not contract["submit_readiness"].strip()):
        raise ValueError("Invalid CI submit-readiness description")
    suite = contract.get("golden_standard_suite")
    if suite is not None:
        if not isinstance(suite, dict):
            raise ValueError("Invalid golden-suite contract")
        if suite.get("manifest") is not None and not _safe_relative(suite["manifest"]):
            raise ValueError("Golden-suite manifest must be repository relative")
        for key in ("required_files",):
            if key in suite and not _string_list(suite[key], path_values=True):
                raise ValueError("Invalid golden-suite files")
        if "required_markers" in suite:
            _validate_marker_map(suite["required_markers"])
    local = contract.get("local_gate_profile")
    if local is not None:
        if not isinstance(local, dict) or not isinstance(local.get("profile_id"), str) or not local["profile_id"].strip() or not _safe_relative(local.get("manifest", "")):
            raise ValueError("Invalid local gate profile")
        if local.get("covered_by") is not None and (not isinstance(local["covered_by"], str) or not local["covered_by"].strip()):
            raise ValueError("Invalid local gate coverage")
        if "required_markers" in local and not _string_list(local["required_markers"]):
            raise ValueError("Invalid local gate markers")
    groups = contract.get("industry_gate_groups", {})
    if not isinstance(groups, dict):
        raise ValueError("Invalid industry gate groups")
    for group_name, group in groups.items():
        if not isinstance(group_name, str) or not group_name.strip() or not isinstance(group, dict):
            raise ValueError("Invalid industry gate group")
        for key in ("required_markers", "industry_references"):
            if key in group and not _string_list(group[key]):
                raise ValueError("Invalid industry gate group list")
        if group.get("covered_by") is not None and (not isinstance(group["covered_by"], str) or not group["covered_by"].strip()):
            raise ValueError("Invalid industry gate coverage")
    if "required_files" in contract and not _string_list(contract["required_files"], path_values=True):
        raise ValueError("Invalid CI contract files")
    if "marker_files" in contract:
        _validate_marker_map(contract["marker_files"])


def _validate_marker_map(value):
    if not isinstance(value, dict):
        raise ValueError("Marker requirements must be an object")
    for path, markers in value.items():
        if not _safe_relative(path) or not _string_list(markers):
            raise ValueError("Invalid marker requirement")


def validate_policy_profile(profile):
    """Validate central profile policy and explicitly supplied local profiles."""
    policy = profile.get("repository_policy", {})
    if not isinstance(policy, dict) or set(policy) - POLICY_FIELDS:
        raise ValueError("Invalid repository policy fields")
    if "require_workflow" in policy and type(policy["require_workflow"]) is not bool:
        raise ValueError("Workflow requirement must be a boolean")
    if "data_profile" in policy and policy["data_profile"] not in DATA_PROFILES:
        raise ValueError("Unknown repository data profile")
    if "documentation_profile" in policy and policy["documentation_profile"] not in DOCUMENTATION_PROFILES:
        raise ValueError("Unknown repository documentation profile")
    if "hygiene_profile" in policy and policy["hygiene_profile"] not in HYGIENE_PROFILES:
        raise ValueError("Unknown repository hygiene profile")
    branch = policy.get("branch")
    if branch is not None:
        if not isinstance(branch, dict) or set(branch) - {"required_refs", "development_bases", "pr_flows"}:
            raise ValueError("Invalid branch policy")
        for key in ("required_refs", "development_bases"):
            if key in branch and (not _string_list(branch[key]) or len(set(branch[key])) != len(branch[key])):
                raise ValueError("Invalid branch policy refs")
        if "pr_flows" in branch:
            flows = branch["pr_flows"]
            if not isinstance(flows, list) or any(not isinstance(flow, dict) or set(flow) != {"head", "base"} or not all(isinstance(flow[k], str) and flow[k].strip() for k in ("head", "base")) for flow in flows):
                raise ValueError("Invalid branch flow policy")
            if len({flow["head"] for flow in flows}) != len(flows):
                raise ValueError("Duplicate managed branch flow")
    license_policy = policy.get("license")
    if license_policy is not None:
        if not isinstance(license_policy, dict) or set(license_policy) - {"label", "spdx", "text_markers", "files", "metadata_files", "notice_files", "notice_markers"}:
            raise ValueError("Invalid license policy")
        for key in ("spdx", "text_markers", "files", "metadata_files", "notice_files", "notice_markers"):
            if key in license_policy and not _string_list(license_policy[key], path_values=key in {"files", "metadata_files", "notice_files"}):
                raise ValueError("Invalid license policy list")
    dependencies = policy.get("dependencies")
    if dependencies is not None:
        if not isinstance(dependencies, dict) or set(dependencies) - {"manifest_globs", "boundary_files", "required_marker_groups", "warning_terms", "ignored_parts"}:
            raise ValueError("Invalid dependency policy")
        for key in ("manifest_globs", "boundary_files", "required_marker_groups", "warning_terms", "ignored_parts"):
            if key in dependencies and not _string_list(dependencies[key], path_values=key == "boundary_files"):
                raise ValueError("Invalid dependency policy list")
    inventory = policy.get("project_inventory")
    if inventory is not None:
        if not isinstance(inventory, dict) or set(inventory) - {"audit_profile", "technology_stack", "internal_components", "open_source_components", "dependency_manifests", "security_boundaries"}:
            raise ValueError("Invalid project inventory")
        if not isinstance(inventory.get("audit_profile"), str) or not inventory["audit_profile"].strip():
            raise ValueError("Project inventory must declare its audit profile")
        for key in ("technology_stack", "internal_components", "open_source_components", "dependency_manifests", "security_boundaries"):
            if key in inventory and not _string_list(inventory[key], path_values=key == "dependency_manifests"):
                raise ValueError("Invalid project inventory list")
        for key in ("technology_stack", "internal_components", "open_source_components", "dependency_manifests"):
            if not inventory.get(key):
                raise ValueError("Project inventory lists must be non-empty")
    if "resource_contracts" in policy:
        _validate_resource_contracts(policy["resource_contracts"])
    if "ci_contract" in policy:
        _validate_ci_contract(policy["ci_contract"])
    server = policy.get("server_boundary")
    if server is not None:
        if not isinstance(server, dict) or set(server) - {"restricted_path_globs", "scan_suffixes", "required_manifest_groups", "ignored_parts"}:
            raise ValueError("Invalid server boundary policy")
        for key in ("restricted_path_globs", "scan_suffixes", "required_manifest_groups", "ignored_parts"):
            if key in server and not _string_list(server[key], path_values=False):
                raise ValueError("Invalid server boundary policy list")
    defects = policy.get("defect_records")
    if defects is not None:
        if not isinstance(defects, dict) or set(defects) - {"root", "required_audit_fields", "required_closure_fields", "closed_statuses"} or not _safe_relative(defects.get("root", "")):
            raise ValueError("Invalid defect-record policy")
        for key in ("required_audit_fields", "required_closure_fields", "closed_statuses"):
            if not _string_list(defects.get(key)) or len(set(defects[key])) != len(defects[key]):
                raise ValueError("Invalid defect-record policy list")
    admissions = policy.get("json_admissions", [])
    if not isinstance(admissions, list) or any(not isinstance(item, dict) or set(item) != {"path", "kind"} or not _safe_relative(item["path"]) or item["kind"] not in {"config-object", "json", "string-array", "string-map"} for item in admissions):
        raise ValueError("Invalid exact JSON admissions")
    if len({item["path"] for item in admissions}) != len(admissions):
        raise ValueError("Duplicate JSON admission")
    if not _string_list(policy.get("schema_fixtures", []), path_values=True):
        raise ValueError("Invalid synthetic schema fixture paths")
    _validate_privacy_policy(profile)


def _validate_privacy_policy(profile):
    exceptions = profile.get("privacy_exceptions", [])
    if not isinstance(exceptions, list):
        raise ValueError("Privacy exceptions must be a list")
    seen = set()
    for entry in exceptions:
        if not isinstance(entry, dict) or set(entry) != {"rule", "path", "value", "reason", "source"}:
            raise ValueError("Invalid privacy exception")
        if any(not isinstance(entry[key], str) or not entry[key] for key in entry):
            raise ValueError("Privacy exception fields must be non-empty strings")
        if not _safe_relative(entry["path"]):
            raise ValueError("Privacy exception path must be normalized and repository-relative")
        key = (entry["rule"], entry["path"], entry["value"])
        if key in seen:
            raise ValueError("Duplicate privacy exception")
        seen.add(key)
    privacy = profile.get("privacy_policy", {})
    if not isinstance(privacy, dict) or set(privacy) - {"privacy_ip_allowlist", "privacy_domain_allowlist"}:
        raise ValueError("Invalid privacy policy")
    ip_entries = privacy.get("privacy_ip_allowlist", [])
    domain_entries = privacy.get("privacy_domain_allowlist", [])
    if not isinstance(ip_entries, list) or not isinstance(domain_entries, list):
        raise ValueError("Privacy allowlists must be lists")
    for entry in ip_entries:
        if not isinstance(entry, dict) or set(entry) != {"service", "ips", "path_globs"} or not isinstance(entry.get("service"), str) or not entry["service"].strip() or not _string_list(entry.get("ips")) or not _string_list(entry.get("path_globs")):
            raise ValueError("Invalid IP privacy allowlist entry")
        try:
            for address in entry["ips"]:
                ipaddress.ip_address(address)
        except ValueError as error:
            raise ValueError("Invalid IP privacy allowlist address") from error
    for entry in domain_entries:
        if not isinstance(entry, dict) or set(entry) != {"host", "path_globs", "schemes"} or not isinstance(entry.get("host"), str) or not re.fullmatch(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", entry["host"]) or not _string_list(entry.get("path_globs")) or not _string_list(entry.get("schemes")) or any(scheme not in {"http", "https"} for scheme in entry["schemes"]):
            raise ValueError("Invalid domain privacy allowlist entry")


def _path_matches(path, pattern):
    if "|" in pattern:
        return any(_path_matches(path, choice) for choice in pattern.split("|"))
    if not any(char in pattern for char in "*?["):
        return path == pattern or path.startswith(pattern.rstrip("/") + "/")
    return fnmatchcase(path, pattern)


def _matches_any(path, patterns):
    return any(_path_matches(path, pattern) for pattern in patterns)


def _json_object(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate JSON key")
        data[key] = value
    return data


def _json_constant(value):
    raise ValueError("non-finite JSON constant")


def _path_profile(pattern, path):
    if pattern == "common":
        return path in COMMON_JSON_NAMES or any(re.fullmatch(item, path) for item in COMMON_JSON_PATTERNS)
    if pattern == "website":
        return _path_profile("common", path)
    if pattern == "licoup":
        return _path_profile("common", path) or path in LICOUP_EXACT_JSON_PATHS or any(re.fullmatch(item, path) for item in LICOUP_JSON_PATTERNS)
    if pattern == "badtower":
        return _path_profile("common", path) or any(re.fullmatch(item, path) for item in BADTOWER_JSON_PATTERNS)
    if pattern == "licoarc":
        return _path_profile("common", path) or any(re.fullmatch(item, path) for item in LICOARC_JSON_PATTERNS)
    return False


def _json_shape_ok(profile_name, path, data):
    if isinstance(data, list):
        return ((profile_name == "licoup" and path in LICOUP_JSON_LIST_PATHS)
                or path.startswith("conformance/") or path.startswith("tools/registry/capability-acceptance-checkpoints/")
                or path.startswith("docs/reports/") or path.startswith("packages/contracts/src/fixtures/"))
    if not isinstance(data, dict):
        return False
    if not data:
        return True
    name = PurePosixPath(path).name
    keys = set(data)
    if path == "tools/release/source-version.json":
        if keys != {"schemaVersion", "versionSources", "changelog", "tagPrefix"} or data.get("schemaVersion") != 1 or not isinstance(data.get("changelog"), str) or not isinstance(data.get("tagPrefix"), str) or not isinstance(data.get("versionSources"), list) or not data["versionSources"]:
            return False
        for source in data["versionSources"]:
            if not isinstance(source, dict) or not isinstance(source.get("path"), str):
                return False
            source_keys = set(source)
            if source_keys == {"path", "pointer"} and isinstance(source.get("pointer"), str):
                continue
            if source_keys == {"format", "path", "key"} and source.get("format") == "toml" and isinstance(source.get("key"), str):
                continue
            if source_keys == {"format", "path", "pattern"} and source.get("format") == "regex" and isinstance(source.get("pattern"), str):
                continue
            return False
        return True
    if re.fullmatch(r"workflow-templates/[a-z0-9][a-z0-9._-]*\.properties\.json", path):
        if not {"name", "description"} <= keys or not keys <= {"name", "description", "iconName", "categories", "filePatterns"}:
            return False
        return all(isinstance(data.get(key), str) and 0 < len(data[key]) <= maximum for key, maximum in (("name", 160), ("description", 320)))
    if name in {"mcp.json", ".mcp.json", "server.json"}:
        return "mcpServers" in keys
    if name in {"package.json", "package-lock.json"}:
        return bool(keys & {"name", "version", "scripts", "dependencies", "devDependencies", "lockfileVersion", "packages"})
    if name.startswith("tsconfig") and name.endswith(".json"):
        return bool(keys & {"compilerOptions", "extends", "files", "include", "references"})
    if path.startswith("contracts/") and name.endswith(".schema.json"):
        return {"$schema", "type"} <= keys
    if path.startswith("policies/"):
        return "policyVersion" in keys or bool(keys & JSON_MARKERS)
    if path.startswith("artifacts/") or path.startswith("vendor/"):
        return {"artifactVersion", "digest", "digestAlgorithm"} <= keys
    if path.startswith("conformance/"):
        return bool(keys)
    if profile_name == "licoup":
        if re.fullmatch(r"tools/apple-release/[^/]+\.json", path):
            return data.get("schema") == "apple-release.config.v1" and all(isinstance(data.get(key), expected) for key, expected in (("source", dict), ("version", dict), ("gates", list), ("build", dict), ("apple", dict), ("github", dict), ("artifacts", list)))
        if path == "vscode/settings.json":
            return bool(keys)
        if path == "apps/desktop/assets/update/licoup-update-public-keys.json":
            return keys == {"keys"} and isinstance(data.get("keys"), dict)
        if re.fullmatch(r"crates/licoup-native/src/domain/agent_intelligence_catalog/[^/]+\.json", path):
            return "source_url" in keys and "last_updated" in keys and bool(keys & {"models", "variants"})
        if path == "crates/licoup-native/src/domain/provider_model_pricing/pricing_snapshot.json":
            return {"schema_version", "snapshot_date", "providers"} <= keys
        if path == "crates/licoup-native/src/domain/provider_model_pricing/pricing_catalog.json":
            return {"agents", "last_updated", "providers"} <= keys
    if re.fullmatch(r"modules/[^/]+/module\.json", path):
        return {"module_id", "module_type"} <= keys
    if path.startswith("tools/registry/schema/") and name.endswith(".schema.json"):
        return {"$schema", "type", "properties"} <= keys
    return bool(keys & JSON_MARKERS)


def _schema_only_sql(text):
    # Quoted values and comments do not define SQL commands. Inspect every
    # statement, including multiple statements on one line, without execution.
    tokens = re.sub(r"--[^\n]*|/\*.*?\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"", " ", text, flags=re.S)
    return all(not statement.strip() or re.match(r"(?i)\s*(?:CREATE|ALTER|DROP|PRAGMA|BEGIN|COMMIT|END)\b", statement) for statement in tokens.split(";"))


def _line_for(text, pattern):
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else None


def _markdown_target(source_path, raw_target):
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"): target = target[1:-1].strip()
    else: target = target.split(maxsplit=1)[0] if target else ""
    if not target or target.startswith(("#", "//")) or EXTERNAL_LINK.match(target): return None
    target = unquote(target.split("#", 1)[0].split("?", 1)[0]).strip()
    parts = []
    for part in (PurePosixPath(source_path).parent / target).parts:
        if part in {"", "."}: continue
        if part == "..":
            if parts: parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _markdown_links_to(text, target_path):
    for match in MARKDOWN_LINK.finditer(text):
        if match.group(0).startswith("!"): continue
        raw = match.group(1).strip()
        if raw.startswith("<") and raw.endswith(">"): raw = raw[1:-1].strip()
        else: raw = raw.split(maxsplit=1)[0]
        raw = unquote(raw.split("#", 1)[0].split("?", 1)[0]).rstrip("/")
        if raw == target_path or raw.endswith("/" + target_path): return True
    return False


def _ignore_matches(pattern, path):
    pattern = pattern.strip().lstrip("/")
    if not pattern or pattern.startswith("#"): return False
    directory = pattern.endswith("/") or pattern.endswith("/**")
    pattern = pattern.rstrip("/")
    if directory:
        return path == pattern or path.startswith(pattern + "/") or any(part == pattern for part in PurePosixPath(path).parts)
    if "/" not in pattern:
        return any(fnmatchcase(part, pattern) for part in PurePosixPath(path).parts)
    return fnmatchcase(path, pattern) or path.startswith(pattern.rstrip("*") .rstrip("/" ) + "/")


def _ignored_by_candidate(path, gitignore_texts):
    ignored = False
    for text in gitignore_texts:
        for raw in text.splitlines():
            pattern = raw.strip()
            if not pattern or pattern.startswith("#"): continue
            negate = pattern.startswith("!")
            pattern = pattern[1:] if negate else pattern
            if _ignore_matches(pattern, path): ignored = not negate
    return ignored


def _resource_task(resource):
    machine = resource["state_machine"]
    states = ", ".join(machine["states"])
    tests = ", ".join(resource["required_tests"])
    risks = ", ".join(resource["audit_risks"])
    return (f"Resource `{resource['id']}` ({resource['owner']}) in {', '.join(resource['scope_globs'])}: "
            f"review ownership, copying, concurrency, nullability, cleanup and state transitions "
            f"({states}); assess declared tests ({tests}) and risks ({risks}).")


def _public_finding(rule, path, head, message, *, severity="error", line=None, category="Repository contract", action=None, basis=None):
    safe = redact_path(path)
    return {
        "file": safe, "line": line, "commit": head if isinstance(head, str) else None,
        "rule": rule, "category": category, "severity": severity,
        "evidence": message, "judgment": "unreviewed" if severity == "warning" else "policy_violation",
        "basis": basis or ("An applicable trusted central profile declares this deterministic repository contract." if severity == "error" else "A content or metadata indicator is a review signal; the value itself is withheld and does not prove a violation."),
        "impact": "Potential policy or disclosure risk; confirm scope and context locally.",
        "action": action or "Review the cited file or metadata and correct the contract or centrally maintained profile.",
    }


def evaluate(repository, profile, paths, read_text, event):
    """Evaluate a selected central profile against immutable candidate metadata.

    `read_text` is called at most once for each requested path. An unreadable or
    unavailable text blob creates an explicit coverage gap rather than a pass.
    """
    validate_policy_profile(profile)
    policy = profile.get("repository_policy", {})
    event = event if isinstance(event, Mapping) else {}
    rows = {}
    for row in paths:
        path = row.get("path") if isinstance(row, Mapping) else None
        if isinstance(path, str): rows[path] = dict(row)
    names = set(rows)
    head = event.get("head") or event.get("head_sha")
    findings = []
    evaluated, blocking, incomplete = set(), set(), []
    exempted = []
    text_cache = {}

    def read(path, rule):
        if path in text_cache: return text_cache[path]
        row = rows.get(path)
        if row is None: return None
        if row.get("kind") not in {None, "blob"} or row.get("mode") == "120000":
            incomplete.append({"rule": rule, "path": path, "reason": "non-text Git object"})
            text_cache[path] = None
            return None
        try:
            value = read_text(path)
        except (OSError, UnicodeError, ValueError):
            value = None
        if not isinstance(value, str) or "\x00" in value:
            incomplete.append({"rule": rule, "path": path, "reason": "text unavailable"})
            value = None
        text_cache[path] = value
        return value

    def add(rule, path, message, *, severity="error", line=None, category="Repository contract", action=None, basis=None):
        row = _public_finding(rule, path, head, message, severity=severity, line=line, category=category, action=action, basis=basis)
        findings.append(row)
        if severity == "error": blocking.add(rule)

    def mark(rule): evaluated.add(rule)

    if policy.get("require_workflow"):
        rule = "repository.general-auditor-workflow"
        mark(rule)
        path = ".github/workflows/general-auditor.yml"
        if path not in names:
            add(rule, path, "The required General-Auditor workflow is missing from this candidate.")
        else:
            text = read(path, rule)
            if text is not None:
                required = (
                    re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*Unka-Malloc/General-Auditor@only\s*(?:#.*)?$"),
                    re.compile(r"(?m)^\s*push:\s*(?:#.*)?$"),
                    re.compile(r"(?m)^\s*pull_request:\s*(?:#.*)?$"),
                    re.compile(r"(?m)^\s*fetch-depth:\s*0\s*(?:#.*)?$"),
                    re.compile(r"(?m)^\s*persist-credentials:\s*false\s*(?:#.*)?$"),
                )
                if not all(pattern.search(text) for pattern in required):
                    add(rule, path, "The General-Auditor workflow does not match the maintained functional entry-point contract.")

    required_paths = profile.get("required_paths", [])
    if required_paths:
        rule = "repository.required-path"
        mark(rule)
        for path in required_paths:
            if not any(candidate == path or candidate.startswith(path.rstrip("/") + "/") for candidate in names):
                add(rule, path, "A path declared by this repository profile is absent from the candidate.")

    if policy.get("hygiene_profile") == "styio-default":
        rule = "repository.hygiene"
        mark(rule)
        max_bytes = 5 * 1024 * 1024
        for path, row in rows.items():
            parts = set(PurePosixPath(path).parts)
            name = PurePosixPath(path).name
            size = row.get("size")
            bad = name in STYIO_FORBIDDEN_NAMES or bool(parts & STYIO_FORBIDDEN_PARTS) or name.endswith(STYIO_FORBIDDEN_SUFFIXES)
            if bad:
                add(rule, path, "A temporary, generated, cache, archive or raw-data artifact is present in the repository tree.", action="Remove the artifact from source control and retain it only in an appropriate ignored or artifact location.", category="Repository hygiene")
            elif isinstance(size, int) and size > max_bytes:
                add(rule, path, "The repository file exceeds the declared 5 MiB source-size limit.", action="Move large generated artifacts or datasets to artifact storage, or review the centrally maintained exception scope.", category="Repository hygiene")

    data_profile = policy.get("data_profile")
    if data_profile:
        rule = "repository.data-file-admission"
        mark(rule)
        for path in sorted(names):
            suffix = PurePosixPath(path).suffix.lower()
            if suffix in BINARY_DATA_SUFFIXES:
                add(rule, path, "A database, spreadsheet, columnar file or binary data artifact is not an admitted source format.", category="Data-file policy", action="Keep datasets and generated binary data outside Git or use a reviewed synthetic fixture format.")
                continue
            if suffix in DATA_DUMP_SUFFIXES:
                allowed_fixture = data_profile == "licoup" and any(re.fullmatch(pattern, path) for pattern in LICOUP_SYNTHETIC_DATA_PATTERNS)
                if path in policy.get("schema_fixtures", []):
                    fixture = read(path, rule)
                    allowed_fixture = fixture is not None and _schema_only_sql(fixture)

                if allowed_fixture:
                    exempted.append({"rule": rule, "path": path, "count": 1})
                else:
                    add(rule, path, "A tabular, SQL dump or line-delimited data export is not admitted by this repository profile.", category="Data-file policy", action="Remove exported data or move a synthetic fixture to a centrally approved path.")
            if suffix != ".json" or not rows[path].get("kind") in {None, "blob"}:
                continue
            normalized = path.lower()
            admission = next((item for item in policy.get("json_admissions", []) if item["path"] == path), None)
            allowed = admission is not None or _path_profile(data_profile, normalized)
            if not allowed:
                add("repository.json-not-allowlisted", path, "This repository profile does not admit JSON at this path by default.", category="Data-file policy", action="Use an approved configuration, schema, manifest or synthetic fixture path; update only the central profile after review.")
                continue
            text = read(path, "repository.json-configuration")
            if text is None: continue
            try:
                data = json.loads(text, object_pairs_hook=_json_object, parse_constant=_json_constant)
            except (ValueError, RecursionError):
                add("repository.json-invalid", path, "An allowlisted JSON file is not strict valid JSON.", category="Data-file policy")
                continue
            if admission is not None:
                kind = admission["kind"]
                shape_ok = (isinstance(data, dict) if kind == "config-object" else
                            isinstance(data, (dict, list)) if kind == "json" else
                            isinstance(data, list) and len(data) <= 1000 and all(isinstance(v, str) and bool(v.strip()) for v in data) if kind == "string-array" else
                            isinstance(data, dict) and len(data) <= 1000 and all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()))
            else:
                shape_ok = _json_shape_ok(data_profile, normalized, data)
            if not shape_ok:
                add("repository.json-shape-invalid", path, "An allowlisted JSON file does not have an approved configuration or fixture shape.", category="Data-file policy")

    doc_profile = policy.get("documentation_profile")
    if doc_profile:
        doc_paths = sorted(path for path in names if path.startswith("docs/") and path.lower().endswith(".md"))
        for path in LICO_REQUIRED_PATHS:
            rule = "repository.documentation-required-path"
            mark(rule)
            if path not in names: add(rule, path, "A required public documentation entry point is missing.", category="Documentation governance")
        for source, target in (("README.md", "README.zh-CN.md"), ("README.zh-CN.md", "README.md")):
            if source not in names or target not in names: continue
            rule = "repository.documentation-readme-cross-link"
            mark(rule)
            text = read(source, rule)
            if text is not None and not _markdown_links_to(text, target):
                add(rule, source, "The paired root README does not link to its counterpart.", category="Documentation governance")
        for prefix in LICO_REQUIRED_SECTIONS:
            rule = "repository.documentation-required-section"
            mark(rule)
            if not any(path.startswith(prefix) for path in doc_paths):
                add(rule, prefix, "A required formal documentation section has no tracked Markdown file.", category="Documentation governance")
        for path in sorted(names):
            if any(path.startswith(prefix) for prefix in LICO_LOCAL_PREFIXES):
                mark("repository.documentation-local-asset")
                add("repository.documentation-local-asset", path, "A local plan, report, cache or build output is tracked in the public repository.", category="Documentation governance")
            if path.startswith(("skills/", ".agents/skills/", ".codex/skills/")) and PurePosixPath(path).name == "SKILL.md":
                mark("repository.documentation-agent-entrypoint")
                add("repository.documentation-agent-entrypoint", path, "A repository-local Agent bundle is outside the approved public product locations.", category="Documentation governance")
            if path.startswith("docs/") and path.lower().endswith(".md"):
                formal = path in LICO_FORMAL_FILES or any(path.startswith(prefix) for prefix in LICO_FORMAL_PREFIXES)
                if doc_profile == "licoup": formal = formal or path in LICOUP_FORMAL_FILES or any(path.startswith(prefix) for prefix in LICOUP_FORMAL_PREFIXES)
                if path not in {"docs/README.md"} and path not in {p for p in LICO_FORMAL_FILES if p.startswith("docs/")} and not _localized_formal(path) and not formal:
                    mark("repository.documentation-formal-path")
                    add("repository.documentation-formal-path", path, "Formal project Markdown is outside the repository's approved documentation categories.", category="Documentation governance")
        gitignore_texts = []
        for path in sorted(names):
            if PurePosixPath(path).name == ".gitignore":
                text = read(path, "repository.documentation-local-asset-ignore")
                if text is not None: gitignore_texts.append(text)
        for sentinel in LICO_IGNORE_SENTINELS:
            mark("repository.documentation-local-asset-ignore")
            if sentinel in names:
                add("repository.documentation-local-asset-ignore", sentinel, "A local-only documentation or build asset is tracked.", category="Documentation governance")
            elif not _ignored_by_candidate(sentinel, gitignore_texts):
                add("repository.documentation-local-asset-ignore", str(PurePosixPath(sentinel).parent) + "/", "The repository does not ignore this local-only asset directory.", category="Documentation governance")
        markdown = {}
        for path in doc_paths:
            text = read(path, "repository.documentation-markdown-read")
            if text is not None: markdown[path] = text
        for path, text in markdown.items():
            for match in MARKDOWN_LINK.finditer(text):
                target = _markdown_target(path, match.group(1))
                if target is None: continue
                mark("repository.documentation-link-target")
                if target not in names and not any(candidate.startswith(target.rstrip("/") + "/") for candidate in names):
                    add("repository.documentation-link-target", path, "A local Markdown link does not resolve inside the candidate tree.", severity="warning", line=text.count("\n", 0, match.start()) + 1, category="Documentation")
            if not (path.endswith(".generated.md") or GENERATED_MARKER.search(text)): continue
            if not GENERATED_SOURCE.search(text):
                mark("repository.documentation-generated-source")
                add("repository.documentation-generated-source", path, "Generated documentation does not identify its canonical source.", category="Documentation governance")
            if not GENERATED_UPDATE.search(text):
                mark("repository.documentation-generated-update")
                add("repository.documentation-generated-update", path, "Generated documentation does not describe how it is updated.", category="Documentation governance")

    if policy.get("branch", {}).get("required_refs"):
        rule = "repository.branch-required-ref"
        mark(rule)
        refs = event.get("branch_refs")
        if not isinstance(refs, list):
            incomplete.append({"rule": rule, "scope": "branch_refs", "reason": "complete branch inventory unavailable"})
        else:
            branches = {ref.removeprefix("refs/heads/") for ref in refs if isinstance(ref, str) and ref.startswith("refs/heads/")}
            for branch in policy["branch"]["required_refs"]:
                if branch not in branches:
                    add(rule, "<branch-ref>", "A centrally required repository branch is not present in the verified ref inventory.", category="Branch governance")
    branch_policy = policy.get("branch", {})
    flows = branch_policy.get("pr_flows", [])
    if flows and event.get("trigger") in {"pull_request", "pull_request_target"}:
        rule = "repository.branch-promotion-flow"
        mark(rule)
        base_ref, head_ref = event.get("base_ref"), event.get("head_ref")
        if not isinstance(base_ref, str) or not base_ref or not isinstance(head_ref, str) or not head_ref:
            incomplete.append({"rule": rule, "scope": "pull_request_refs", "reason": "pull request base/head refs unavailable"})
        else:
            mapping = {flow["head"]: flow["base"] for flow in flows}
            development_bases = set(branch_policy.get("development_bases", []))
            allowed_bases = development_bases | set(mapping.values()) | set(mapping.keys())
            reserved = set(mapping) | set(mapping.values()) | development_bases
            if base_ref not in allowed_bases:
                add(rule, "<pull-request>", "The pull request targets a branch outside this repository's declared development/promotion flow.", category="Branch governance")
            expected = mapping.get(head_ref)
            if expected is not None and expected != base_ref:
                add(rule, "<pull-request>", "A managed promotion branch targets a base other than its declared next branch.", category="Branch governance")
            required_heads = {head for head, base in mapping.items() if base == base_ref}
            if expected is None and head_ref in reserved and head_ref not in development_bases:
                add(rule, "<pull-request>", "A managed promotion branch is used outside its declared flow.", category="Branch governance")
            if expected is None and base_ref not in development_bases and required_heads:
                add(rule, "<pull-request>", "This promoted branch accepts pull requests only from its declared predecessor.", category="Branch governance")

    # Lico contribution indicators are deliberately advisory: names and
    # attribution metadata are signals, not automatic authorship judgments.
    for path in sorted(names):
        if PurePosixPath(path).suffix.lower() not in {".md", ".json", ".toml", ".yaml", ".yml", ".txt", ".xml"}:
            continue
        text = read(path, "contribution.cursor-attribution")
        if text is None: continue
        line_offsets = [0]
        line_offsets.extend(match.end() for match in re.finditer("\n", text))
        contributor_context = path.rsplit("/", 1)[-1].lower() in {".all-contributorsrc", ".mailmap", "authors", "authors.md", "authors.txt", "contributors", "contributors.md", "contributors.txt"}
        for match in CURSOR_IDENTITY.finditer(text):
            line = text[text.rfind("\n", 0, match.start()) + 1:text.find("\n", match.start()) if text.find("\n", match.start()) >= 0 else len(text)]
            prefix = text[max(0, match.start() - 1024):match.start()]
            heading = list(CONTRIBUTOR_HEADING.finditer(prefix))
            context = contributor_context or bool(COMMIT_TRAILER.match(line)) or bool(CONTRIBUTOR_FIELD.search(prefix[-1024:])) or (bool(heading) and not re.search(r"(?m)^#{1,6}\s+", prefix[heading[-1].end():]))
            if context:
                mark("contribution.cursor-attribution")
                add("contribution.cursor-attribution", path, "Contributor or attribution metadata contains an automated-tool identity signal.", severity="warning", line=text.count("\n", 0, match.start()) + 1, category="Contributor metadata", action="Check the attribution context and publication policy; the identity text is withheld and is not treated as a leak or verdict.")
                break
    commit_metadata = event.get("commit_metadata")
    if isinstance(commit_metadata, list):
        for item in commit_metadata:
            if not isinstance(item, Mapping): continue
            values = [item.get("author_name"), item.get("committer_name"), *item.get("trailers", [])] if isinstance(item.get("trailers", []), list) else [item.get("author_name"), item.get("committer_name")]
            if any(isinstance(value, str) and CURSOR_IDENTITY.search(value) for value in values):
                mark("contribution.commit-attribution")
                add("contribution.commit-attribution", "<commit-metadata>", "Commit attribution contains an automated-tool identity signal.", severity="warning", category="Contributor metadata", action="Review commit attribution locally; author names, email addresses and trailer text are withheld.")
                break
    branch_refs = event.get("branch_refs")
    if isinstance(branch_refs, list):
        mark("contribution.branch-prefix")
        for ref in branch_refs:
            if not isinstance(ref, str): continue
            name = ref.removeprefix("refs/heads/") if ref.startswith("refs/heads/") else ref
            if name.casefold() == "codex" or name.casefold().startswith(("codex/", "codex-", "codex_")):
                add("contribution.branch-prefix", "<branch-ref>", "A branch name matches a legacy automated-tool naming signal.", severity="warning", category="Branch metadata", action="Use a meaningful temporary branch name if the contributor policy requires it; the branch name alone is not an authorship verdict.")
                break
    elif policy.get("branch") or commit_metadata is None:
        incomplete.append({"rule": "contribution.branch-prefix", "scope": "branch_refs", "reason": "complete branch inventory unavailable"})

    license_policy = policy.get("license")
    if license_policy:
        rule = "repository.license-evidence"
        mark(rule)
        files = license_policy.get("files", list(LICENSE_FILES))
        existing = sorted(set(files) & names)
        spdx = [item.casefold() for item in license_policy.get("spdx", ["Apache-2.0"])]
        markers = [item.casefold() for item in license_policy.get("text_markers", ["Apache License", "Version 2.0"])]
        if not existing:
            add(rule, files[0], "No declared source-license file is present.", category="License evidence")
        else:
            valid = False
            for path in existing:
                text = read(path, rule)
                if text is not None:
                    lowered = text.casefold()
                    valid |= any(identifier in lowered for identifier in spdx) or all(marker in lowered for marker in markers)
            if not valid:
                add(rule, existing[0], "The declared source-license file does not contain the required license evidence.", category="License evidence")
        for path in license_policy.get("metadata_files", list(LICENSE_METADATA_FILES)):
            if path not in names: continue
            text = read(path, rule)
            if text is None: continue
            value = _metadata_license(path, text)
            if value is None:
                add(rule, path, "Package metadata does not declare the required source license.", category="License evidence")
            elif not (any(identifier in value.casefold() for identifier in spdx) or all(marker in value.casefold() for marker in markers)):
                add(rule, path, "Package metadata declares a license outside this repository's source-license contract.", category="License evidence")
        notice_files = license_policy.get("notice_files", list(LICENSE_NOTICE_FILES))
        notice_markers = [item.casefold() for item in license_policy.get("notice_markers", ["Apache", "License", "Version 2.0"])]
        notice_found = False
        for path in notice_files:
            if path not in names: continue
            text = read(path, rule)
            if text is not None and all(marker in text.casefold() for marker in notice_markers): notice_found = True
        if not notice_found:
            add(rule, notice_files[0], "No source-distribution notice contains the required license markers.", category="License evidence", action="Restore license and source-distribution notice evidence required by the Styio source policy.")

    dependency_policy = policy.get("dependencies")
    if dependency_policy:
        rule = "repository.dependency-boundary-evidence"
        mark(rule)
        manifest_globs = dependency_policy.get("manifest_globs", list(DEPENDENCY_GLOBS))
        manifest_paths = sorted(path for path in names if _matches_any(path, manifest_globs) and not set(PurePosixPath(path).parts) & set(dependency_policy.get("ignored_parts", ("node_modules", "vendor", "build", "dist", ".git"))))
        boundary_paths = [path for path in dependency_policy.get("boundary_files", list(DEPENDENCY_BOUNDARY_FILES)) if path in names]
        if not boundary_paths:
            add(rule, dependency_policy.get("boundary_files", list(DEPENDENCY_BOUNDARY_FILES))[0], "Dependency license and usage-boundary evidence is missing.", category="Dependency governance")
        else:
            boundary_texts = [read(path, rule) for path in boundary_paths]
            if any(text is None for text in boundary_texts):
                pass
            else:
                boundary = "\n".join(boundary_texts).casefold()
                for group in dependency_policy.get("required_marker_groups", list(DEPENDENCY_MARKER_GROUPS)):
                    if not _marker_group_matches(boundary, group):
                        add(rule, boundary_paths[0], "Dependency usage-boundary documentation is missing a required topic.", category="Dependency governance")
                dependency_names = {}
                for path in manifest_paths:
                    text = read(path, rule)
                    if text is None: continue
                    for term in dependency_policy.get("warning_terms", list(COMMERCIAL_TERMS)):
                        if term.casefold() in text.casefold():
                            add("repository.dependency-commercial-signal", path, "A dependency manifest contains a commercial-use term that requires contextual review.", severity="warning", category="Dependency governance", action="Review the dependency's actual license and use conditions; the term alone is not a violation.")
                    for name in _dependencies(path, text): dependency_names.setdefault(name.casefold(), path)
                for name, path in dependency_names.items():
                    if name not in boundary:
                        add(rule, path, "A declared dependency is not named in dependency usage-boundary evidence.", category="Dependency governance", action="Record license and usage-boundary evidence for every declared direct dependency.")

    if policy.get("resource_contracts"):
        rule = "repository.resource-scope"
        mark(rule)
        for resource in policy["resource_contracts"]:
            if not any(_matches_any(path, resource["scope_globs"]) for path in names):
                add(rule, resource["scope_globs"][0], "A centrally declared resource contract scope matches no source file in this candidate.", category="Resource lifecycle", action="Update the trusted resource scope or restore its implementation files.")

    ci = policy.get("ci_contract")
    if ci:
        _evaluate_ci_contract(ci, names, rows, read, add, mark, incomplete)
        readiness = ci.get("submit_readiness")
        if readiness:
            # The executable job, golden-suite and marker gates above validate
            # the actual contract; this string adds a human review topic only.
            pass

    server = policy.get("server_boundary")
    if server:
        restricted = server.get("restricted_path_globs", list(SERVER_RESTRICTED_GLOBS))
        rule = "repository.server-material-path"
        mark(rule)
        for path in sorted(names):
            if _matches_any(path, restricted) and not any(marker.casefold() in path.casefold() for marker in SERVER_ALLOWED_NAME_MARKERS):
                add(rule, path, "A path identifies deployment or secret material that must remain outside a public repository.", category="Server boundary", action="Keep credentials, deployment state and private operational material in approved local or secret-management storage.")
        marker_rule = "repository.server-boundary-manifest"
        mark(marker_rule)
        inventory = policy.get("project_inventory", {})
        declared_boundaries = "\n".join(inventory.get("security_boundaries", [])).casefold()
        for group in server.get("required_manifest_groups", list(BACKEND_MANIFEST_MARKERS)):
            if not _marker_group_matches(declared_boundaries, group):
                add(marker_rule, "<central-profile>", "The trusted backend profile omits a required security-boundary topic.", category="Server boundary", action="Complete the centrally maintained profile contract before using it.")
        rule = "repository.server-security-signal"
        mark(rule)
        suffixes = set(server.get("scan_suffixes", sorted(SERVER_SCAN_SUFFIXES)))
        ignored = set(server.get("ignored_parts", (".git", ".dart_tool", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__", "build", "dist", "node_modules", "venv")))
        for path in sorted(names):
            if PurePosixPath(path).suffix.lower() not in suffixes or set(PurePosixPath(path).parts) & ignored: continue
            text = read(path, rule)
            if text is None: continue
            normalized = re.sub(r"\s+", " ", text.casefold())
            for category, terms in SERVER_DANGEROUS_MARKERS.items():
                if any(re.sub(r"\s+", " ", term.casefold()) in normalized for term in terms):
                    add(rule, path, "A source-code security marker requires contextual review.", severity="warning", category="Server security", action="Determine whether this is executable behavior, a negative test, documentation, or another benign reference; marker matches never block by themselves.")

    defect_policy = policy.get("defect_records")
    if defect_policy:
        rule = "repository.defect-record-closure"
        mark(rule)
        root = defect_policy["root"].rstrip("/") + "/"
        closed_statuses = {status.casefold() for status in defect_policy["closed_statuses"]}
        for path in sorted(path for path in names if path.startswith(root)):
            if path == root[:-1]: continue
            if not path.lower().endswith(".md"):
                add(rule, path, "A defect record under the audit defect directory must be Markdown.", category="Defect closure")
                continue
            text = read(path, rule)
            if text is None: continue
            status = re.search(r"(?im)^\*\*Status:\*\*\s*(.+?)\s*$", text)
            for field in defect_policy["required_audit_fields"]:
                if not _field_has_value(text, field):
                    add(rule, path, "An audit defect record is missing a required audit field.", category="Defect closure", line=_line_for(text, re.compile(re.escape(field))))
            if status is None:
                add(rule, path, "An audit defect record has no explicit status.", category="Defect closure")
                continue
            if status.group(1).strip().casefold() not in closed_statuses:
                add(rule, path, "An audit defect record is not in a closed status.", category="Defect closure", line=text.count("\n", 0, status.start()) + 1)
                continue
            for field in defect_policy["required_closure_fields"]:
                if not _field_has_value(text, field):
                    add(rule, path, "A closed audit defect record is missing required closure evidence.", category="Defect closure", line=_line_for(text, re.compile(re.escape(field))))
            closure = re.search(r"(?im)^\*\*Closure evidence:\*\*\s*(.+?)\s*$", text)
            if closure is None or closure.group(1).strip().casefold() in {"", "tbd", "todo", "none", "n/a"}:
                add(rule, path, "A closed audit defect record has empty closure evidence.", category="Defect closure")

    review_tasks = list(profile.get("local_review", []))
    for resource in policy.get("resource_contracts", []):
        review_tasks.append(_resource_task(resource))
    if policy.get("server_boundary"):
        review_tasks.append("Review authentication, privacy, permissions, runtime secret custody, deployment security, dependency vulnerabilities, DAST, rate limiting, log redaction, SSRF/egress controls and command-execution boundaries in affected server code.")
    if policy.get("dependencies"):
        review_tasks.append("Review each direct dependency's license evidence, provenance, commercial-use limits and actual usage scope; textual matches remain advisory.")
    if policy.get("ci_contract"):
        review_tasks.append("Review required platform adaptations, smoke tests, golden-suite cases and project-specific gate groups against the preserved CI status contract.")
    for item in [*incomplete, *exempted]:
        if "path" in item: item["path"] = redact_path(item["path"])
    return {
        "privacy_policy": dict(profile.get("privacy_policy", {})),
        "findings": findings,
        "coverage": {"evaluated": sorted(evaluated), "blocking": sorted(blocking), "incomplete": incomplete, "exempted": exempted},
        "review_tasks": review_tasks,
    }


def _localized_formal(path):
    return any(formal.endswith(".md") and path == formal[:-3] + ".zh-CN.md" for formal in LICO_FORMAL_FILES)


def _marker_group_matches(text, group):
    return any(alternative and re.sub(r"\s+", " ", alternative.casefold()) in re.sub(r"\s+", " ", text.casefold()) for alternative in group.split("|"))


def _field_has_value(text, field):
    return re.search(r"(?m)^" + re.escape(field) + r"\s*\S+", text) is not None


def _metadata_license(path, text):
    name = PurePosixPath(path).name
    if name == "package.json":
        try: data = json.loads(text)
        except ValueError: return None
        license_value = data.get("license") if isinstance(data, dict) else None
        if isinstance(license_value, str): return license_value
        if isinstance(license_value, dict): return " ".join(str(value) for value in license_value.values() if isinstance(value, str))
        return None
    if name == "pyproject.toml":
        try:
            import tomllib
            data = tomllib.loads(text)
        except (ImportError, ValueError): return None
        project = data.get("project", {}) if isinstance(data, dict) else {}
        value = project.get("license") if isinstance(project, dict) else None
        if isinstance(value, str): return value
        if isinstance(value, dict): return " ".join(str(item) for item in value.values() if isinstance(item, str))
        return None
    if name == "pubspec.yaml":
        match = re.search(r"(?m)^\s*license\s*:\s*(.+?)\s*$", text)
        return match.group(1).strip().strip("'\"") if match else None
    return None


def _dependencies(path, text):
    name = PurePosixPath(path).name
    result = set()
    if name in {"package.json", "package-lock.json"}:
        try: data = json.loads(text)
        except ValueError: return result
        if isinstance(data, dict):
            for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                if isinstance(data.get(group), dict): result.update(str(item) for item in data[group])
    elif name == "pyproject.toml":
        try:
            import tomllib
            data = tomllib.loads(text)
        except (ImportError, ValueError): return result
        project = data.get("project", {}) if isinstance(data, dict) else {}
        if isinstance(project, dict):
            for dep in project.get("dependencies", []):
                if isinstance(dep, str): result.add(re.split(r"[<>=!~;\[]", dep, 1)[0].strip())
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for values in optional.values():
                    for dep in values if isinstance(values, list) else []:
                        if isinstance(dep, str): result.add(re.split(r"[<>=!~;\[]", dep, 1)[0].strip())
    elif name == "Cargo.toml":
        section = ""
        for line in text.splitlines():
            match = re.match(r"\s*\[([^]]+)\]", line)
            if match: section = match.group(1).split(".", 1)[0]; continue
            if section in {"dependencies", "dev-dependencies", "build-dependencies"}:
                match = re.match(r"\s*([A-Za-z0-9_-]+)\s*=", line)
                if match: result.add(match.group(1))
    elif name == "go.mod":
        result.update(re.findall(r"(?m)^\s*(?:require\s+)?([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+)\s+v", text))
    elif name.startswith("requirements") and name.endswith(".txt"):
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-")):
                result.add(re.split(r"[<>=!~;\[]", line, 1)[0].strip())
    elif name == "pubspec.yaml":
        in_group = False
        for line in text.splitlines():
            if re.match(r"^(dependencies|dev_dependencies):\s*$", line): in_group = True; continue
            if in_group and line and not line[0].isspace(): in_group = False
            if in_group:
                match = re.match(r"^\s{2}([A-Za-z0-9_-]+):", line)
                if match: result.add(match.group(1))
    elif name == "vcpkg.json":
        try: data = json.loads(text)
        except ValueError: return result
        if isinstance(data, dict) and isinstance(data.get("dependencies"), list):
            result.update(item if isinstance(item, str) else item.get("name") for item in data["dependencies"] if isinstance(item, str) or isinstance(item, dict) and isinstance(item.get("name"), str))
    elif name == "Package.swift":
        result.update(re.findall(r"\.package\s*\(\s*url\s*:\s*\"[^\"]+/(?:[^/]+)\"", text))
    return {item for item in result if isinstance(item, str) and item}


def _evaluate_ci_contract(contract, names, rows, read, add, mark, incomplete):
    jobs = []
    workflow_rule = "repository.ci-gate-contract"
    workflow_paths = sorted(path for path in names if path.startswith(".github/workflows/") and PurePosixPath(path).suffix.lower() in {".yml", ".yaml"})
    for path in workflow_paths:
        text = read(path, workflow_rule)
        if text is None: continue
        workflow_name = ""
        in_jobs = False
        current = None
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"): continue
            if not line.startswith(" ") and line.startswith("name:"):
                workflow_name = line.split(":", 1)[1].strip().strip("'\"")
            if line == "jobs:":
                in_jobs, current = True, None
                continue
            if not in_jobs: continue
            if not line.startswith(" "):
                if current: jobs.append(current)
                current, in_jobs = None, False
                continue
            match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
            if match:
                if current: jobs.append(current)
                current = {"id": match.group(1), "name": match.group(1), "runs_on": "", "path": path, "workflow": workflow_name}
            elif current:
                match = re.match(r"^    name:\s*(.+)$", line)
                if match: current["name"] = match.group(1).strip().strip("'\"")
                match = re.match(r"^    runs-on:\s*(.+)$", line)
                if match: current["runs_on"] = match.group(1).strip().strip("'\"")
        if current: jobs.append(current)
    def gate(name): return [job for job in jobs if job["name"] == name]
    def require_gate(name, label):
        mark(workflow_rule)
        found = gate(name)
        if len(found) != 1:
            add(workflow_rule, ".github/workflows/", f"The declared {label} must appear exactly once in the candidate workflows.", category="CI gate contract")
            return None
        return found[0]
    for path in contract.get("required_files", []):
        mark("repository.ci-required-file")
        if path not in names:
            add("repository.ci-required-file", path, "A required project delivery file is missing.", category="CI gate contract")
    for path, markers in contract.get("marker_files", {}).items():
        mark("repository.ci-required-marker")
        if path not in names:
            add("repository.ci-required-marker", path, "A required project delivery marker file is missing.", category="CI gate contract")
            continue
        text = read(path, "repository.ci-required-marker")
        if text is not None:
            normalized = re.sub(r"\s+", " ", text.casefold())
            for marker in markers:
                if not _marker_group_matches(normalized, marker):
                    add("repository.ci-required-marker", path, "A required project delivery marker is missing.", category="CI gate contract")
    for platform, name in contract.get("platform_adaptation", {}).items():
        job = require_gate(name, "platform gate")
        if job:
            normalized = job["runs_on"].casefold()
            markers = {"linux": ("ubuntu", "linux"), "macos": ("macos", "macos"), "windows": ("windows",)}.get(platform.casefold(), ())
            if markers and not any(marker in normalized for marker in markers):
                add(workflow_rule, job["path"], "A required platform gate runs on a runner that does not match its declared platform.", category="CI gate contract")
    for name in contract.get("classified_gates", []): require_gate(name, "classified release gate")
    for label, name in contract.get("test_gates", {}).items(): require_gate(name, f"{label} test gate")
    suite = contract.get("golden_standard_suite", {})
    suite_paths = list(suite.get("required_files", []))
    if suite.get("manifest"): suite_paths.insert(0, suite["manifest"])
    for path in dict.fromkeys(suite_paths):
        mark("repository.ci-golden-suite")
        if path not in names:
            add("repository.ci-golden-suite", path, "A required golden-suite file is missing.", category="CI gate contract")
    for path, markers in suite.get("required_markers", {}).items():
        mark("repository.ci-golden-suite")
        if path not in names:
            add("repository.ci-golden-suite", path, "A required golden-suite marker file is missing.", category="CI gate contract")
            continue
        text = read(path, "repository.ci-golden-suite")
        if text is not None:
            normalized = re.sub(r"\s+", " ", text.casefold())
            for marker in markers:
                if not _marker_group_matches(normalized, marker):
                    add("repository.ci-golden-suite", path, "A required golden-suite marker is missing.", category="CI gate contract")
    local = contract.get("local_gate_profile")
    if local:
        path = local["manifest"]
        mark("repository.ci-local-gate-profile")
        if path not in names:
            add("repository.ci-local-gate-profile", path, "The project-local gate profile manifest is missing.", category="CI gate contract")
        else:
            text = read(path, "repository.ci-local-gate-profile")
            if text is not None:
                normalized = re.sub(r"\s+", " ", text.casefold())
                markers = [local["profile_id"], "local gate profile", *local.get("required_markers", [])]
                for marker in markers:
                    if not _marker_group_matches(normalized, marker):
                        add("repository.ci-local-gate-profile", path, "The project-local gate profile is missing a required marker.", category="CI gate contract")
        if local.get("covered_by"):
            require_gate(local["covered_by"], "local gate profile coverage")
    golden_manifest = suite.get("manifest")
    golden_text = read(golden_manifest, "repository.ci-industry-groups") if golden_manifest and golden_manifest in names else None
    for group, spec in contract.get("industry_gate_groups", {}).items():
        mark("repository.ci-industry-groups")
        if spec.get("covered_by"): require_gate(spec["covered_by"], "industry gate coverage")
        if golden_manifest and golden_text is None:
            incomplete.append({"rule": "repository.ci-industry-groups", "path": golden_manifest, "reason": "golden-suite marker text unavailable"})
        elif golden_text is not None:
            normalized = re.sub(r"\s+", " ", golden_text.casefold())
            for marker in [group, *spec.get("required_markers", [])]:
                if not _marker_group_matches(normalized, marker):
                    add("repository.ci-industry-groups", golden_manifest, "A required industry gate-group marker is missing from the golden suite.", category="CI gate contract")
