"""Redact sensitive identifiers from repository-relative location strings."""

from pathlib import PureWindowsPath
import re

from .providers import _TOKEN_COMBINED


_EMAIL = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{1,64}@"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![A-Z0-9_-])"
)
_LOCAL_HOME = re.compile(
    r"(?i)/(?:Users|home)/[^/\s]+(?:/[^\s]*)?|"
    r"[A-Z]:[\\/]Users[\\/][^\\/\s]+(?:[\\/][^\s]*)?|"
    r"\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\s]*)?"
)
_LOCAL_VOLUME = re.compile(r"(?i)/(?:Volumes|private/var/folders|private/var/tmp)/[^\s]+")
_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
    r"client[_-]?secret|secret[_-]?key|credential|bearer|token|session[_-]?key)"
    r"([:=._-])[^/\\\s]+"
)
_PRIVATE_MARKER = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:::[0-9A-Fa-f:]{0,})?(?![0-9A-Fa-f:.])")
_LONG_RANDOM_COMPONENT = re.compile(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{48,}(?![A-Fa-f0-9])")


def redact_path(path: str) -> str:
    """Return a useful relative location while removing sensitive path content."""
    value = re.sub(r"[\x00-\x1f\x7f]", "_", str(path)).replace("\\", "/")
    if value.startswith("/") or re.match(r"^[A-Za-z]:/", value) or PureWindowsPath(value).is_absolute():
        return "[absolute-path]"
    value = _LOCAL_HOME.sub("[local-path]", value)
    value = _LOCAL_VOLUME.sub("[local-path]", value)
    value = _EMAIL.sub("[redacted-email]", value)
    value = _PRIVATE_MARKER.sub("[private-key]", value)
    value = _TOKEN_COMBINED.sub("[credential]", value)
    value = _ASSIGNMENT.sub("[credential]", value)
    value = _IPV4.sub("[redacted-ip]", value)
    value = _IPV6.sub("[redacted-ip]", value)
    value = _LONG_RANDOM_COMPONENT.sub("[redacted-id]", value)
    return value
