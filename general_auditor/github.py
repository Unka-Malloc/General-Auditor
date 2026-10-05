"""Read public metadata; never collect PR bodies, comments or runtime logs."""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .config import OWNERS, repository_name
from .gitdata import SHA


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

    def repositories(self):
        result = []
        for owner in OWNERS:
            for row in self.pages("/orgs/" + owner + "/repos", type="public"):
                if row.get("private") or row.get("visibility") != "public":
                    continue
                name = repository_name(row["full_name"])
                if name.split("/")[0].lower() != owner.lower():
                    raise APIError("Repository owner does not match the inventory scope")
                result.append({"repository": name, "default_branch": row["default_branch"],
                               "archived": row["archived"], "visibility": "public"})
        return sorted(result, key=lambda row: row["repository"].lower())

    def candidates(self, repository, default_branch, *, all_refs=True):
        repository_name(repository)
        prefix = "/repos/" + repository
        candidates = []
        if all_refs:
            try:
                branches = list(self.pages(prefix + "/branches"))
            except APIError as error:
                if error.status != 409:
                    raise
                branches = []
        else:
            branches = [self.get(prefix + "/branches/" + quote(default_branch, safe=""))]
        if not branches:
            return [{"key": repository + ":empty", "repository": repository, "head": None,
                     "base": None, "trigger": "empty_repository", "default": True}]
        for row in branches:
            head = row["commit"]["sha"]
            if not SHA.fullmatch(head):
                raise APIError("Invalid branch commit identity")
            candidates.append({"key": repository + ":branch:" + row["name"], "repository": repository,
                               "head": head, "base": None, "trigger": "branch", "default": row["name"] == default_branch})
        if all_refs:
            for row in self.pages(prefix + "/pulls", state="open"):
                # Fork commits are fetched through the public upstream PR object.
                if row["head"].get("repo") and row["head"]["repo"].get("private"):
                    continue
                head, base = row["head"]["sha"], row["base"]["sha"]
                if not SHA.fullmatch(head) or not SHA.fullmatch(base):
                    raise APIError("Invalid pull request commit identity")
                candidates.append({"key": repository + ":pr:" + str(row["number"]), "repository": repository,
                                   "head": head, "base": base, "trigger": "pull_request", "default": False})
        return candidates
