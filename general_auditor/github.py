"""Read public metadata; never collect PR bodies, comments or runtime logs."""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .config import repository_name
from .governance import RULESET_NAME, violations


class APIError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class GitHub:
    def __init__(self, token=None):
        self.token = token if token is not None else os.environ.get("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
        self.opener = build_opener(NoRedirect())

    def get(self, path, **params):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Expected a GitHub API path")
        url = "https://api.github.com" + path
        if params:
            url += "?" + urlencode(params)
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "General-Auditor"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        try:
            with self.opener.open(Request(url, headers=headers)) as response:
                return json.load(response)
        except (HTTPError, URLError, ValueError) as error:
            # Do not echo request headers or potentially sensitive API response bodies.
            code = error.code if isinstance(error, HTTPError) else "unavailable"
            raise APIError("GitHub metadata request failed (" + str(code) + ")", status=code) from None

    def pages(self, path, **params):
        page = 1
        while True:
            rows = self.get(path, per_page=100, page=page, **params)
            if not isinstance(rows, list):
                raise APIError("Invalid GitHub list response")
            yield from rows
            if len(rows) < 100:
                break
            page += 1

    def access_policy(self, repository):
        repository_name(repository)
        prefix = "/repos/" + repository
        metadata = self.get(prefix)
        matching = [row for row in self.pages(prefix + "/rulesets") if row["name"] == RULESET_NAME]
        ruleset = self.get(prefix + "/rulesets/" + str(matching[0]["id"])) if len(matching) == 1 else None
        return violations(metadata, ruleset)
