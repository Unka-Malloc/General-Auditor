"""Portable, structural checks for key containers and web-key formats."""

import base64
import binascii
import json
import re
import struct
from collections.abc import Iterator, Mapping
from json.decoder import scanstring

from .providers import is_placeholder
from .types import Candidate


_PRIVATE_PEM = re.compile(
    r"-----BEGIN (?P<label>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
    r"(?P<body>[\s\S]*?)-----END (?P=label)-----"
)
_PRIVATE_PEM_MARKER = re.compile(
    r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
)
_PRIVATE_PGP_MARKER = re.compile(r"-----BEGIN PGP PRIVATE KEY(?: BLOCK)?-----")
_SSH_PUBLIC = re.compile(
    r"(?<![\w-])(?P<kind>ssh-rsa|ssh-ed25519|ssh-dss|"
    r"ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|"
    r"ssh-rsa-cert-v01@openssh\.com|ssh-ed25519-cert-v01@openssh\.com|"
    r"ecdsa-sha2-nistp256-cert-v01@openssh\.com|ecdsa-sha2-nistp384-cert-v01@openssh\.com|"
    r"ecdsa-sha2-nistp521-cert-v01@openssh\.com|"
    r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
    r"[ \t]+(?P<blob>[A-Za-z0-9+/]+={0,2})(?![A-Za-z0-9+/=])"
)
_COMPACT_JOSE = re.compile(r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_-]+\.){2}(?:[A-Za-z0-9_-]*)(?![A-Za-z0-9_.-])")
_COMPACT_JWE = re.compile(r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_-]*\.){4}[A-Za-z0-9_-]*(?![A-Za-z0-9_.-])")


def _decode_b64url(value: str, *, allow_empty: bool = False) -> bytes:
    if (not value and not allow_empty) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("invalid base64url segment")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _pem_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    seen: set[int] = set()
    for match in _PRIVATE_PEM.finditer(text):
        body = match.group("body").replace("\\r\\n", "\n").replace("\\n", "\n")
        body_lines = [line.strip() for line in body.splitlines() if line.strip()]
        payload_lines = [line for line in body_lines if not line.lower().startswith(("proc-type:", "dek-info:"))]
        encoded = "".join(payload_lines)
        syntactic = False
        if encoded:
            try:
                raw = base64.b64decode(encoded, validate=True)
                syntactic = bool(raw)
            except (ValueError, binascii.Error):
                pass
        start, end = match.span()
        seen.add(start)
        basis = "Delimited private-key container with syntactically valid payload" if syntactic else "Private-key container requiring structural review"
        yield Candidate(start, end, basis, ((start, end),))
    for marker in (*_PRIVATE_PEM_MARKER.finditer(text), *_PRIVATE_PGP_MARKER.finditer(text)):
        span = marker.span()
        if span[0] not in seen:
            yield Candidate(*span, "Private-key container marker", (span,))


def _ssh_string(data: bytes, position: int) -> tuple[bytes, int]:
    if position + 4 > len(data):
        raise ValueError("truncated SSH field")
    length = struct.unpack_from(">I", data, position)[0]
    end = position + 4 + length
    if end > len(data):
        raise ValueError("truncated SSH field")
    return data[position + 4:end], end


def _valid_ssh_public(kind: str, encoded: str) -> bool:
    try:
        raw = base64.b64decode(encoded, validate=True)
        embedded, position = _ssh_string(raw, 0)
        if embedded.decode("ascii") != kind:
            return False
        if kind in {"ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"}:
            public, position = _ssh_string(raw, position)
            if len(public) != 32:
                return False
            return position == len(raw) if kind == "ssh-ed25519" else position < len(raw)
        if kind in {"ssh-rsa", "ssh-rsa-cert-v01@openssh.com"}:
            exponent, position = _ssh_string(raw, position)
            modulus, position = _ssh_string(raw, position)
            return bool(exponent and modulus) and (position == len(raw) if kind == "ssh-rsa" else position < len(raw))
        if kind.startswith("ecdsa-sha2-"):
            curve, position = _ssh_string(raw, position)
            point, position = _ssh_string(raw, position)
            expected = kind.removeprefix("ecdsa-sha2-").removesuffix("-cert-v01@openssh.com")
            return curve.decode("ascii") == expected and bool(point) and (
                position == len(raw) if "-cert-v01@" not in kind else position < len(raw)
            )
        # Security-key public material has additional fields. The embedded type
        # and complete wire encoding still provide a stable advisory signal.
        return position < len(raw)
    except (ValueError, UnicodeError, binascii.Error, struct.error):
        return False


def _ssh_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for match in _SSH_PUBLIC.finditer(text):
        if not _valid_ssh_public(match.group("kind"), match.group("blob")):
            continue
        yield Candidate(*match.span(), "Structurally valid SSH public-key material", (match.span(),))


def _json_key_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    """Find private JWK members with one pass over JSON object/string structure."""

    stack: list[dict[str, object]] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "{":
            stack.append({"fields": [], "start": index})
            index += 1
            continue
        if char == "}":
            if stack:
                obj = stack.pop()
                fields = obj["fields"]
                if not isinstance(fields, list):
                    index += 1
                    continue
                key_type = next((value for key, value, _start, _end in fields if key == "kty"), None)
                if key_type in {"RSA", "EC", "OKP", "oct"}:
                    private_members = {
                        "RSA": {"d", "p", "q", "dp", "dq", "qi", "oth"},
                        "EC": {"d"},
                        "OKP": {"d"},
                        "oct": {"k"},
                    }[key_type]
                    for key, value, start, end in fields:
                        if key in private_members and value and not is_placeholder(value):
                            yield Candidate(start, end, "JWK object contains private or symmetric key material", ((start, end),))
            index += 1
            continue
        if char != '"':
            index += 1
            continue
        try:
            key, key_end = scanstring(text, index + 1, True)
        except (ValueError, json.JSONDecodeError):
            index += 1
            continue
        cursor = key_end
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text) or text[cursor] != ":":
            index = key_end
            continue
        cursor += 1
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor < len(text) and text[cursor] == '"':
            try:
                value, value_end = scanstring(text, cursor + 1, True)
            except (ValueError, json.JSONDecodeError):
                index = key_end
                continue
            if stack:
                fields = stack[-1]["fields"]
                if isinstance(fields, list):
                    fields.append((key, value, cursor + 1, value_end - 1))
            index = value_end
        else:
            index = key_end


def _jose_json_segment(segment: str) -> object:
    return json.loads(_decode_b64url(segment).decode("utf-8"))


def _jws_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for match in _COMPACT_JOSE.finditer(text):
        token = match.group()
        if is_placeholder(token):
            continue
        parts = token.split(".")
        try:
            header = _jose_json_segment(parts[0])
            payload = _jose_json_segment(parts[1])
        except (ValueError, UnicodeError, json.JSONDecodeError, binascii.Error):
            continue
        if not isinstance(header, dict) or not isinstance(header.get("alg"), str) or not header["alg"]:
            continue
        if not isinstance(payload, dict) or bool(parts[2]) == (header["alg"].casefold() == "none"):
            continue
        try:
            _decode_b64url(parts[2], allow_empty=True)
        except (ValueError, binascii.Error):
            continue
        yield Candidate(*match.span(), "Structurally valid compact JSON web token; authenticity not verified", (match.span(),))


def _jwe_candidates(text: str, _path: str, _profile: Mapping[str, object]) -> Iterator[Candidate]:
    for match in _COMPACT_JWE.finditer(text):
        token = match.group()
        if is_placeholder(token):
            continue
        parts = token.split(".")
        if len(parts) != 5:
            continue
        try:
            header = _jose_json_segment(parts[0])
            _decode_b64url(parts[1], allow_empty=True)
            _decode_b64url(parts[2])
            _decode_b64url(parts[3])
            _decode_b64url(parts[4])
        except (ValueError, UnicodeError, json.JSONDecodeError, binascii.Error):
            continue
        if not isinstance(header, dict) or not header.get("alg") or not header.get("enc"):
            continue
        if not parts[1] and header["alg"] not in {"dir", "ECDH-ES"}:
            continue
        yield Candidate(*match.span(), "Structurally valid encrypted JSON web token", (match.span(),))


def key_rules():
    return (
        ("privacy.key.private-pem", "Private key material", "Private-key PEM or OpenPGP private-key marker", _pem_candidates),
        ("privacy.key.ssh-public", "Public key material", "Structurally valid SSH public-key record", _ssh_candidates),
        ("privacy.key.private-jwk", "Private key material", "JWK private or symmetric key member", _json_key_candidates),
        ("privacy.token.signed-jose", "Credentials", "Compact JSON web token", _jws_candidates),
        ("privacy.token.encrypted-jose", "Credentials", "Encrypted compact JSON web token", _jwe_candidates),
    )
