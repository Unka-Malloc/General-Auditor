"""Portable privacy rule coverage using synthetic source strings only."""

import base64
import json
import struct
import unittest
from dataclasses import FrozenInstanceError

from general_auditor.detection import RULE_CATALOG, redact_path, rule_catalog, scan_text


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


class PrivacyDetectorTests(unittest.TestCase):
    def by_rule(self, result, rule):
        return [finding for finding in result["findings"] if finding["rule"] == rule]

    def test_catalog_is_static_common_and_source_free(self):
        catalog = rule_catalog()
        self.assertIs(catalog, RULE_CATALOG)
        self.assertTrue(catalog)
        self.assertEqual(len({row.id for row in catalog}), len(catalog))
        self.assertTrue(all(row.group == "common" for row in catalog))
        with self.assertRaises(FrozenInstanceError):
            catalog[0].id = "changed"

    def test_provider_literals_remain_advisory_inside_test_examples(self):
        literal = "synthetic-provider-value"
        result = scan_text(
            f'OPENAI_API_KEY="{literal}"\n',
            "tests/examples/config.py",
        )
        findings = self.by_rule(result, "privacy.credential.provider.openai")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding["line"], finding["column"]), (1, 17))
        self.assertEqual(finding["judgment"], "unreviewed")
        self.assertEqual(finding["severity"], "warning")
        self.assertNotIn(literal, json.dumps(result, default=lambda item: item.as_dict()))
        self.assertTrue(result["semantic_review"])

    def test_references_and_placeholders_are_excluded_without_keyword_suppression(self):
        text = "\n".join((
            'OPENAI_API_KEY="${OPENAI_API_KEY}"',
            "GITHUB_TOKEN=process.env.GITHUB_TOKEN",
            'password="replace-me"',
            'client_secret="<configured>"',
            'note="example text is not a value"',
        ))
        result = scan_text(text, "examples/reference-config.env")
        self.assertEqual(result["findings"], [])

    def test_generic_authentication_and_multiline_literals_are_detected_once(self):
        text = '\n'.join((
            'authorization: Bearer synthetic-auth-value-41',
            'client_secret = "first-line\nsecond-line"',
        ))
        result = scan_text(text, "config/settings.yml")
        self.assertEqual(len(self.by_rule(result, "privacy.credential.auth-header")), 1)
        self.assertEqual(len(self.by_rule(result, "privacy.credential.binding")), 1)
        self.assertFalse(self.by_rule(result, "privacy.credential.provider.openai"))

    def test_large_full_text_blob_has_no_detector_size_cap(self):
        marker = 'api_key="synthetic-large-blob-value"'
        text = ("x" * (1_100_000)) + "\n" + marker
        result = scan_text(text, "data/generated.txt")
        finding = self.by_rule(result, "privacy.credential.binding")[0]
        self.assertEqual(finding["line"], 2)
        self.assertEqual(finding["column"], 10)
        self.assertGreater(finding["span"]["end"], 1_000_000)

    def test_format_token_is_recognized_without_validity_checks_or_echo(self):
        token = "AKIA" + "A" * 16
        result = scan_text(f"access={token}\n", "config/reference.txt")
        findings = self.by_rule(result, "privacy.credential.format.aws-key-id")
        self.assertEqual(len(findings), 1)
        self.assertNotIn(token, json.dumps(result, default=lambda item: item.as_dict()))

    def test_private_and_public_key_material_are_distinguished_structurally(self):
        private_body = base64.b64encode(b"synthetic-key-payload").decode("ascii")
        public_blob = base64.b64encode(
            _ssh_string(b"ssh-ed25519") + _ssh_string(b"P" * 32)
        ).decode("ascii")
        text = (
            "-----BEGIN PRIVATE KEY-----\n" + private_body + "\n-----END PRIVATE KEY-----\n"
            "ssh-ed25519 " + public_blob + " synthetic-public-comment\n"
        )
        result = scan_text(text, "fixtures/keys.txt")
        self.assertEqual(len(self.by_rule(result, "privacy.key.private-pem")), 1)
        self.assertEqual(len(self.by_rule(result, "privacy.key.ssh-public")), 1)

    def test_private_jwk_members_and_compact_jose_are_detected(self):
        jwk = json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "public-x", "d": "synthetic-private-d"}]})
        header = _b64url(b'{"alg":"HS256"}')
        claims = _b64url(b'{"sub":"synthetic"}')
        jws = f"{header}.{claims}.c2ln"
        jwe_header = _b64url(b'{"alg":"dir","enc":"A128GCM"}')
        jwe = f"{jwe_header}..aXY.Y2lwaGVy.dGFn"
        result = scan_text(jwk + "\n" + jws + "\n" + jwe + "\n", "data/keys.json")
        self.assertEqual(len(self.by_rule(result, "privacy.key.private-jwk")), 1)
        self.assertEqual(len(self.by_rule(result, "privacy.token.signed-jose")), 1)
        self.assertEqual(len(self.by_rule(result, "privacy.token.encrypted-jose")), 1)

    def test_jwk_placeholders_do_not_create_private_key_findings(self):
        result = scan_text('{"kty":"OKP","d":"replace-me"}', "examples/public.json")
        self.assertFalse(self.by_rule(result, "privacy.key.private-jwk"))

    def test_exact_value_and_path_exception_is_counted_without_disclosure(self):
        literal = "synthetic-approved-example"
        profile = {"privacy_exceptions": [{
            "rule": "privacy.credential.provider.openai",
            "path": "config/sample.env",
            "value": literal,
            "reason": "synthetic fixture",
            "source": "reviewed profile",
        }]}
        result = scan_text(f'OPENAI_API_KEY="{literal}"', "config/sample.env", profile=profile)
        self.assertFalse(self.by_rule(result, "privacy.credential.provider.openai"))
        self.assertEqual(result["coverage"]["exempted"], [
            {"rule": "privacy.credential.provider.openai", "count": 1}
        ])
        wrong_path = scan_text(f'OPENAI_API_KEY="{literal}"', "src/sample.env", profile=profile)
        self.assertTrue(self.by_rule(wrong_path, "privacy.credential.provider.openai"))
        self.assertNotIn(literal, json.dumps(result, default=lambda item: item.as_dict()))

    def test_loopback_docs_ips_and_svg_path_data_are_safe_exclusions(self):
        text = '\n'.join((
            "127.0.0.1 ::1 0.0.0.0",
            "192.0.2.10 198.51.100.20 203.0.113.30 2001:db8::5",
            '<svg><path d="M 198.51.100.2 4 203.0.113.8 11" /></svg>',
        ))
        result = scan_text(text, "images/diagram.svg")
        self.assertFalse(self.by_rule(result, "privacy.endpoint.ip-address"))

    def test_ipv4_ipv6_and_scoped_profile_allowlists(self):
        policy = {"privacy_policy": {"privacy_ip_allowlist": [{
            "service": "synthetic-service",
            "ips": ["10.20.30.40"],
            "path_globs": ["examples/service-config.yml"],
        }]}}
        text = "10.20.30.40 10.9.8.7 2001:4860:4860::8888"
        scoped = scan_text(text, "examples/service-config.yml", profile=policy)
        hits = self.by_rule(scoped, "privacy.endpoint.ip-address")
        self.assertEqual(len(hits), 2)
        other_path = scan_text(text, "src/service-config.yml", profile=policy)
        self.assertEqual(len(self.by_rule(other_path, "privacy.endpoint.ip-address")), 3)

    def test_domain_allowlist_is_exact_in_host_scheme_and_path(self):
        policy = {"privacy_policy": {"privacy_domain_allowlist": [{
            "host": "gateway.internal.corp",
            "schemes": ["https"],
            "path_globs": ["docs/**"],
        }]}}
        url = "https://gateway.internal.corp/v1"
        docs = scan_text(url, "docs/endpoints.md", profile=policy)
        self.assertFalse(self.by_rule(docs, "privacy.endpoint.private-host"))
        source = scan_text(url, "src/endpoints.py", profile=policy)
        self.assertEqual(len(self.by_rule(source, "privacy.endpoint.private-host")), 1)
        other_host = scan_text("https://api.gateway.internal.corp/v1", "docs/endpoints.md", profile=policy)
        self.assertEqual(len(self.by_rule(other_host, "privacy.endpoint.private-host")), 1)

    def test_personal_identifiers_and_machine_paths_are_advisory(self):
        text = "contact synthetic.person@example.invalid +12025550142 123-45-6789 4000000000000002\n/Users/synthetic-user/project/data.db"
        result = scan_text(text, "fixtures/runtime.txt")
        self.assertEqual(len(self.by_rule(result, "privacy.personal.identifier")), 4)
        self.assertEqual(len(self.by_rule(result, "privacy.local.machine-path")), 1)
        self.assertTrue(all(item["severity"] == "warning" for item in result["findings"]))

    def test_location_output_redacts_sensitive_path_components(self):
        credential = "ghp_" + "A" * 36
        path = f"docs/synthetic.person@example.invalid/{credential}/10.2.3.4.md"
        redacted = redact_path(path)
        self.assertNotIn("synthetic.person@example.invalid", redacted)
        self.assertNotIn(credential, redacted)
        self.assertNotIn("10.2.3.4", redacted)
        self.assertEqual(redact_path("/Users/synthetic-user/private/file.txt"), "[absolute-path]")

    def test_arbitrary_service_endpoints_and_public_authority_exclusions(self):
        text = "https://node.operator.corp/api wss://node.operator.corp/ws ssh://node.operator.corp/repo"
        result = scan_text(text, "config/hosts.txt")
        self.assertEqual(len(self.by_rule(result, "privacy.endpoint.private-host")), 3)
        examples = "https://localhost/a https://example.com/a https://api.openai.com/a https://docs.github.com/a"
        self.assertFalse(self.by_rule(scan_text(examples, "docs/links.md"), "privacy.endpoint.private-host"))
        self.assertTrue(self.by_rule(scan_text("https://api.openai.com.attacker.corp/a", "docs/links.md"), "privacy.endpoint.private-host"))

    def test_unsigned_jwt_and_embedded_public_key_are_not_lost(self):
        token = _b64url(b'{"alg":"none"}') + "." + _b64url(b'{"sub":"synthetic"}') + "."
        blob = base64.b64encode(_ssh_string(b"ssh-ed25519") + _ssh_string(b"P" * 32)).decode()
        result = scan_text(token + '\nkey = "ssh-ed25519 ' + blob + '"', "config/test.py")
        self.assertEqual(len(self.by_rule(result, "privacy.token.signed-jose")), 1)
        self.assertEqual(len(self.by_rule(result, "privacy.key.ssh-public")), 1)

    def test_unparsed_key_container_still_requires_review_without_duplicate_marker(self):
        text = "-----BEGIN PRIVATE KEY-----\nnot valid base64\n-----END PRIVATE KEY-----"
        hits = self.by_rule(scan_text(text, "fixtures/key.txt"), "privacy.key.private-pem")
        self.assertEqual(len(hits), 1)
        self.assertIn("requiring structural review", hits[0]["basis"])
        valid_body = base64.b64encode(b"synthetic").decode()
        escaped = "-----BEGIN PRIVATE KEY-----\\n" + valid_body + "\\n-----END PRIVATE KEY-----"
        self.assertEqual(len(self.by_rule(scan_text(escaped, "fixtures/key.json"), "privacy.key.private-pem")), 1)

    def test_auth_headers_nats_token_and_query_password_locations(self):
        text = ('"x-goog-api-key": "synthetic-api-value"\n'
                'nats://synthetic-access-value@node.operator.corp\n'
                'postgresql://node.operator.corp/db?password=synthetic-db-value')
        result = scan_text(text, "config/test.txt")
        self.assertEqual(len(self.by_rule(result, "privacy.credential.auth-header")), 2)
        self.assertEqual(len(self.by_rule(result, "privacy.credential.uri-userinfo")), 1)
        reference = 'postgresql://user:%24%7BPASSWORD%7D@localhost/db'
        self.assertFalse(self.by_rule(scan_text(reference, "config/test.txt"), "privacy.credential.uri-userinfo"))

    def test_exact_exception_never_suppresses_other_value_or_rule(self):
        exception = {"rule": "privacy.credential.binding", "path": "x.env", "value": "synthetic-one"}
        result = scan_text('password="synthetic-one"\npassword="synthetic-two"', "x.env", exceptions=[exception])
        self.assertEqual(len(self.by_rule(result, "privacy.credential.binding")), 1)
        self.assertEqual(result["findings"][0]["line"], 2)

    def test_syntax_references_and_rust_namespaces_are_not_literal_values(self):
        text = 'password=os.getenv("PASS")\npassword=config.password\nface::fade\n'
        result = scan_text(text, "src/config.rs")
        self.assertFalse(self.by_rule(result, "privacy.credential.binding"))
        self.assertFalse(self.by_rule(result, "privacy.endpoint.ip-address"))
        self.assertTrue(self.by_rule(scan_text('"face::fade"', "src/config.rs"), "privacy.endpoint.ip-address"))

    def test_example_substring_does_not_exempt_arbitrary_credentials(self):
        result = scan_text('password="example-real-looking-value"', "docs/example.env")
        self.assertTrue(self.by_rule(result, "privacy.credential.binding"))

    def test_legacy_operational_and_business_signals_remain_advisory(self):
        text = ('customer_name="synthetic-customer"\ncluster_name="synthetic-cluster"\n'
                'hostname="node.operator.corp"\nadmin@node.operator.corp:2222\n'
                'resource=12345678-1234-1234-1234-123456789012\n'
                '/srv/synthetic-deployment/private.env\nC:\\DevSpace\\synthetic\\app.txt')
        result = scan_text(text, "deployment/production/settings.env")
        for rule in ("privacy.business.assignment", "privacy.backend.metadata", "privacy.backend.resource-id", "privacy.endpoint.host-binding", "privacy.local.deployment-path"):
            self.assertTrue(self.by_rule(result, rule), rule)
        self.assertTrue(all(row["severity"] == "warning" for row in result["findings"]))
        public = scan_text("/etc/hosts /opt/homebrew/bin/python /tmp/synthetic-fixture-root/file", "docs/portable.md")
        self.assertFalse(self.by_rule(public, "privacy.local.deployment-path"))

    def test_broad_token_shapes_are_candidates_without_format_validity_claim(self):
        token = "sk-" + "S" * 30
        result = scan_text(token, "fixtures/token.txt")
        hits = self.by_rule(result, "privacy.credential.format.candidate-prefix")
        self.assertEqual(len(hits), 1)
        self.assertNotIn(token, json.dumps(result, default=lambda item: item.as_dict()))


if __name__ == "__main__":
    unittest.main()
