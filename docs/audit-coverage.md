# Audit coverage and consolidation

This ledger maps the effective Lico-Auditor and styio-audit check families to
General-Auditor's executable implementation. It includes the maintained public
sources and the unpublished local detector, contextual-review and project-module
enhancements considered during consolidation. It is a navigation and review aid;
check counts and this document do not establish parity by themselves. The final
integrated source review and deterministic regression determine acceptance.

Privacy signals remain advisory. A declared structural contract can fail CI;
missing required input produces an incomplete result. No result proves absence of
private information. The source provenance and scoped license notice are recorded
in [policy sources](policy-sources.md).

## Privacy detectors

The maintained catalog comes from
[`detection.rule_catalog()`](../general_auditor/detection/__init__.py).
Detectors retain rule identities and source locations. The local report path
attaches actual selected source matches and context; the CI boundary emits only
status and counts. The tests use synthetic inputs in
[`test_detection_coverage.py`](../tests/test_detection_coverage.py).

| Source check family | Executable counterpart | Focused regression / retained distinction |
| --- | --- | --- |
| Lico provider credential catalog; Styio credential assignments | `privacy.credential.provider.*`, `privacy.credential.binding` in [providers.py](../general_auditor/detection/providers.py) | `test_provider_literals_remain_advisory_inside_test_examples`; all catalog field aliases, quoted/multiline literals and external references |
| Cloud, repository, chat and provider token shapes | `privacy.credential.format.*` | `test_format_token_is_recognized_without_validity_checks_or_echo`, `test_broad_token_shapes_are_candidates_without_format_validity_claim`; broad candidates are not authenticated provider credentials |
| HTTP Bearer/Basic/API-key/other authentication; signed access URLs | `privacy.credential.auth-header` in [context.py](../general_auditor/detection/context.py) | `test_generic_authentication_and_multiline_literals_are_detected_once`, `test_auth_headers_nats_token_and_query_password_locations`; literal authentication values and query signatures, no requests or signature checks |
| Service URL passwords and NATS access tokens | `privacy.credential.uri-userinfo` | `test_auth_headers_nats_token_and_query_password_locations`; percent-encoded external references remain excluded |
| PEM/OpenSSH/RSA/EC/DSA/PKCS private containers and encrypted material | `privacy.key.private-pem` in [keys.py](../general_auditor/detection/keys.py) | `test_private_and_public_key_material_are_distinguished_structurally`, `test_unparsed_key_container_still_requires_review_without_duplicate_marker`; malformed and escaped containers remain candidates |
| SSH public identity material | `privacy.key.ssh-public` | `test_unsigned_jwt_and_embedded_public_key_are_not_lost`; embedded wire-format records, distinguished from private keys |
| Private or symmetric JWK members | `privacy.key.private-jwk` | `test_private_jwk_members_and_compact_jose_are_detected`, `test_jwk_placeholders_do_not_create_private_key_findings`; nested objects and public-only objects distinguished |
| JWT/JWS and JWE | `privacy.token.signed-jose`, `privacy.token.encrypted-jose` | `test_private_jwk_members_and_compact_jose_are_detected`, `test_unsigned_jwt_and_embedded_public_key_are_not_lost`; unsigned compact tokens included, no authentication or decryption |
| Domain/host bindings, HTTP/WS/SSH/service endpoints, administrative SSH access | `privacy.endpoint.private-host`, `privacy.endpoint.host-binding` | `test_arbitrary_service_endpoints_and_public_authority_exclusions`, `test_legacy_operational_and_business_signals_remain_advisory`; arbitrary service endpoints require context even without a private-looking hostname |
| IPv4 and IPv6 locations | `privacy.endpoint.ip-address` | `test_ipv4_ipv6_and_scoped_profile_allowlists`, `test_loopback_docs_ips_and_svg_path_data_are_safe_exclusions`, `test_syntax_references_and_rust_namespaces_are_not_literal_values` |
| Customer, contract, billing and commercial fields | `privacy.business.assignment` | `test_legacy_operational_and_business_signals_remain_advisory`; a field is a contextual signal, not a business-data disclosure verdict |
| Backend configuration, deployment and provider resource metadata | `privacy.backend.metadata`, `privacy.backend.resource-id` | `test_legacy_operational_and_business_signals_remain_advisory`; operational resource identifiers and metadata remain reviewed |
| Developer accounts, volumes, temporary and deployment paths, Windows workspaces | `privacy.local.machine-path`, `privacy.local.deployment-path` | `test_personal_identifiers_and_machine_paths_are_advisory`, `test_legacy_operational_and_business_signals_remain_advisory`; standard public system paths distinguished |
| Personal, device, session and runtime records | `privacy.personal.record-field`, `privacy.personal.identifier` | `test_personal_identifiers_and_machine_paths_are_advisory`; contextual field signals plus identifier shapes |
| Exact exceptions and safe internal metadata | `scan_text(..., profile=...)`, internal path handling; private reports preserve actual locations | `test_exact_value_and_path_exception_is_counted_without_disclosure`, `test_exact_exception_never_suppresses_other_value_or_rule`, `test_domain_allowlist_is_exact_in_host_scheme_and_path`, `test_location_output_redacts_sensitive_path_components` |

Exact privacy exceptions bind a rule, repository-relative path and matching value.
IP admissions bind exact addresses and path scope with a documented service;
domain admissions bind an exact host, scheme and path scope. A local review
receipt cannot add or broaden those central exceptions. Do not store real secrets
in an exception merely to suppress a warning.

The key implementation is deliberately an offline structural detector, not a
cryptographic key-validity service. It retains suspicious malformed containers
for review rather than silently treating parsing failure as safe. Public key
material is labeled separately. Provider-shape and entropy heuristics never
replace contextual judgment.

## Repository contracts

[`repository_policy.evaluate()`](../general_auditor/repository_policy.py) applies
only the selected trusted profile. Absence of a contract in another repository is
not a violation. Its focused cases are in
[`test_repository_policy.py`](../tests/test_repository_policy.py); integration
with exit statuses is exercised by
[`test_scan_scopes.py`](../tests/test_scan_scopes.py).

| Source check family | Executable counterpart | Focused regression / retained distinction |
| --- | --- | --- |
| Common and project module selection | [config.py](../general_auditor/config.py), central [profiles](../profiles/) | `test_profiles_validate`; `test_only_current_repository_profile_is_loaded` in [test_auditor.py](../tests/test_auditor.py) |
| Required public paths and module resources | `repository.required-path`, `repository.resource-scope`, `_validate_resource_contracts` | `test_missing_required_public_path_is_a_violation`, `test_invalid_resource_transition_rejected`; source scope is checked, lifecycle semantics remain local review tasks |
| Generated/cache/archive/source-size hygiene | `repository.hygiene` | `test_structural_hygiene_and_content_signals_differ`; actual path/size contracts are separate from keyword signals |
| Data-file admission and approved JSON structure | `repository.data-file-admission`, `repository.json-not-allowlisted`, `repository.json-invalid`, `repository.json-shape-invalid` | `test_exact_admission_and_shape_are_enforced`, `test_duplicate_json_is_not_accepted`, `test_schema_fixture_cannot_admit_runtime_rows`; `SchemaDefinitionFixtureTests` verifies exact SQL fixtures admit only table/index definitions, preserving quoted content and denying mutations, triggers, source queries and malformed payloads; `test_removed_historical_data_files_retain_their_format_policy` covers removed binary exports and the historical JSON distinction |
| Documentation locations, entry points, paired READMEs, local-only assets and generated provenance | `repository.documentation-*` | All tracked Markdown except the paired root READMEs receives link/provenance checks; candidate `.gitignore` rules use Git-native nested and negation semantics. Declarations remain specific to profiles that require them |
| Repository-specific branches and promotion flow | `repository.branch-required-ref`, `repository.branch-promotion-flow` | `test_branch_rules_only_apply_to_selected_profile`; a universal release-channel chain is not imposed |
| Attribution indicators | `contribution.cursor-attribution`, `contribution.commit-attribution`, `contribution.branch-prefix` | `test_historical_attribution_retains_removed_files_and_actual_commit_identity` covers source registries, removed files and commit trailers at their actual commits. Every contextual match remains advisory |
| Source license and distribution notice evidence | `repository.license-evidence` | License file, package metadata and notice evidence checked only where declared; [scoped attribution](../NOTICE) does not assign a project-wide license |
| Direct dependency license and usage boundaries | `repository.dependency-boundary-evidence`, `repository.dependency-commercial-signal` | Nine manifest formats retain direct dependency identities, including CMake declarations, Swift names/URLs, Python build/Poetry dependencies and Cargo target/workspace sections (`test_dependency_policy.py`). Malformed required manifests produce incomplete coverage; commercial terms remain warnings |
| Required platform/test/classified gates and delivery files | `repository.ci-gate-contract`, `repository.ci-required-file`, `repository.ci-required-marker` | `test_required_ci_job_detects_missing_gate`; presence and declared runner/gate contracts do not prove the target test ran |
| Golden suite, local gate manifest and industry gate groups | `repository.ci-golden-suite`, `repository.ci-local-gate-profile`, `repository.ci-industry-groups` | `_evaluate_ci_contract` checks declared files/markers/coverage jobs; private local-only declarations are not published as requirements |
| Backend source/security boundary | `repository.server-material-path`, `repository.server-boundary-manifest`, `repository.server-security-signal` | `test_structural_hygiene_and_content_signals_differ`; dangerous-code markers are warnings, not automatic vulnerability findings |
| Defect closure evidence | `repository.defect-record-closure` | `test_defect_closure_evidence_not_just_closed_label`; closed labels alone do not satisfy required evidence |
| Maintainer-only publishing and Auditor contribution authority | [governance.py](../general_auditor/governance.py), [maintained Rulesets](../.github/rulesets/) | [test_governance.py](../tests/test_governance.py) and `test_only_named_maintainer_from_temporary_upstream_branch_can_contribute` in the contribution verification tests |

A policy field, evidence marker or declared state graph is not proof of runtime
behavior. The resource contracts preserve ownership, lifecycle, cleanup,
concurrency and recovery obligations as semantic review tasks; the scanner does
not execute target programs. Public profile migration retains applicable public
contracts and excludes private local-only inventories from publication. Those
exclusions do not establish that private work was reviewed or deleted.

## Scope, review and persistence

| Source capability | General-Auditor counterpart | Deterministic regression |
| --- | --- | --- |
| Candidate, index, working files and history coverage | [scanner.py](../general_auditor/scanner.py), [gitdata.py](../general_auditor/gitdata.py) | `test_staged_and_worktree_are_independent_inputs` includes null commit locations and local review binding; `test_history_retains_deleted_outgoing_content_and_large_text`, `test_subdirectory_invocation_retains_whole_repository_scope`, and `test_local_scopes_before_first_commit_have_no_false_baseline` in [test_scan_scopes.py](../tests/test_scan_scopes.py) |
| Deterministic triage of one saved scan into decision, contract and cleared groups | [triage.py](../general_auditor/triage.py), local `triage.json` and `triage.html` | [test_triage.py](../tests/test_triage.py) covers one conservative class per finding, decision groups retaining every occurrence, deterministic repeat runs, source escaping, CI refusal and the absence of any model or network dependency |
| One closing report over a fleet audit root | [fleet.py](../general_auditor/fleet.py), local `fleet-report.html` outside any work tree | [test_fleet.py](../tests/test_fleet.py) covers discovery, per-rule remedy ranking from value shapes, one unredacted sidebar page, work-tree refusal, CI refusal and an empty root |
| Full text and transient outgoing versions | Same scanner and shared blob analysis | `test_large_full_text_blob_has_no_detector_size_cap`, `test_intermediate_secret_is_seen_even_when_removed_before_head` |
| Eight common privacy-context topics and profile obligations | [review.py](../general_auditor/review.py) | `test_request_covers_lico_topics_detector_tasks_and_profile_obligations` in [test_review.py](../tests/test_review.py) |
| One judgment per finding/task, extra contextual findings and limitations | Scan-bound local request/receipt/report | `test_all_findings_and_all_tasks_must_be_reviewed_exactly_once`, `test_receipt_must_match_exact_scan_scope_and_finding_identity`, `test_incomplete_scan_or_concrete_limitations_never_look_complete` |
| Private exact evidence versus CI status | Local-only source-backed scan and reviewed envelope; summary-only `check` | Local source fidelity, receipt binding and CI isolation tests; a contextual verdict never rewrites the CI result |
| Local report persistence and history | Fixed Git-root `.general-auditor/local/` storage and self-contained HTML | Local persistence, exact source evidence, safe rendering and selected-run isolation tests |
| Report-free CI boundary | `check` CLI and composite action | [test_cli_boundary.py](../tests/test_cli_boundary.py) covers counts/status-only output and CI refusal for local report commands |

Local receipts record submitted judgments. They cannot attest Agent identity,
prove a conversation occurred, certify safety or automatically update exceptions.
The current local report preserves actual source matches and context from the
selected source version. Exact evidence stays in ignored local files; it is not
copied into CI summaries, terminal output or public artifacts. Old redacted
archives cannot establish original values or a completed contextual review. Blocking keyword hooks are replaced by warning-only signals according
to the current policy; declared structural failures and incomplete coverage retain
separate failing statuses.

## Acceptance and retirement boundary

Run `python3 tools/verify.py` on the integrated candidate after source review and
scoped fixes. Targeted tests above locate relevant behavior; they are not a claim
that every contract variation has been independently verified. Actual upstream workflow execution is separate from local engineering checks.
Queued Actions and pending PRs are not execution evidence. The retired hosted
report service is not a maintained capability; independent historical records
remain data, not a compatibility runtime.

Both former auditor repositories are now private and archived. Their dedicated
active profiles have been removed while shared checks and source/license
provenance remain. Old local checkouts and skill routing were cleared only after
independent assets and unpublished work were preserved privately. No private
backup paths or contents are published here.

The [grouped inventory](repositories.md) lists 30 current public upstreams and
the two retired archives. The 38 consumer migration draft PRs remain unmerged;
retirement and consumer default-branch adoption are distinct operational states.
