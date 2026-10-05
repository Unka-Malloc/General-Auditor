"""Independent repository workflows and durable, serialized report publication."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile

from .config import OWNERS, repository_name
from .github import APIError, GitHub
from .report import merge, publish, read_json, timestamp, write_json
from .runner import plan, run
from .scanner import failed_result, utc_now

CENTRAL = "Unka-Malloc/General-Auditor"
CHECKPOINT = "audit-checkpoint"
RESULT_PREFIX = "audit-result-"


def result_name(repository):
    repository_name(repository)
    return RESULT_PREFIX + repository.replace("/", "--")


class Actions:
    """Use runner-provided gh authentication without exporting credentials."""

    def request(self, path, *, method="GET", payload=None, binary=False):
        command = ["gh", "api", "repos/" + CENTRAL + path, "--method", method]
        if payload is not None:
            command += ["--input", "-"]
        response = subprocess.run(command, input=json.dumps(payload).encode() if payload is not None else None, capture_output=True)
        if response.returncode:
            raise APIError("Auditor artifact or workflow operation failed; response withheld")
        return response.stdout if binary else (json.loads(response.stdout) if response.stdout else None)

    def dispatch(self, workflow, inputs):
        self.request("/actions/workflows/" + workflow + "/dispatches", method="POST", payload={"ref": "only", "inputs": inputs})

    def worker_completion(self, run_id):
        """Resolve a notification to the trusted worker's actual scan outcome."""
        if not isinstance(run_id, str) or not run_id.isascii() or not run_id.isdigit() or int(run_id) <= 0:
            raise ValueError("Invalid repository worker run identity")
        run = self.request("/actions/runs/" + run_id)
        if (run.get("path") != ".github/workflows/audit-repository.yml"
                or run.get("head_branch") != "only" or run.get("event") != "workflow_dispatch"
                or run.get("repository", {}).get("full_name") != CENTRAL
                or run.get("head_repository", {}).get("full_name") != CENTRAL):
            raise ValueError("Publication notification is not from the trusted repository worker")
        if run.get("status") != "completed":
            # The notifier dispatches after scan finishes, but its own job may
            # still be closing when the independent publisher starts. Read the
            # finished scan job; do not wait or guess from the run's null result.
            jobs = self.request("/actions/runs/" + run_id + "/attempts/" + str(run["run_attempt"]) + "/jobs?per_page=100")["jobs"]
            scan = next((job for job in jobs if job.get("name") == "scan"), None)
            if scan is None or scan.get("status") != "completed":
                return {}
            run = {**run, "conclusion": scan["conclusion"], "updated_at": scan["completed_at"]}
        return run

    def artifacts(self, name=None):
        from urllib.parse import urlencode
        page = 1
        while True:
            params = {"per_page": 100, "page": page}
            if name:
                params["name"] = name
            rows = self.request("/actions/artifacts?" + urlencode(params))["artifacts"]
            for row in rows:
                source = row.get("workflow_run", {})
                if not row["expired"] and source.get("head_branch") == "only" and source.get("head_repository_id") == source.get("repository_id") and source.get("repository_id"):
                    yield row
            if len(rows) < 100:
                return
            page += 1

    def latest(self, name):
        return max(self.artifacts(name), key=lambda row: (row["created_at"], row["id"]), default=None)

    def read(self, artifact, names):
        archive = self.request("/actions/artifacts/" + str(artifact["id"]) + "/zip", binary=True)
        # Read named JSON members directly. Never extract paths or execute artifacts.
        with ZipFile(BytesIO(archive)) as stream:
            return {name: json.loads(stream.read(name)) for name in names}

    def restore(self, root):
        artifact = self.latest(CHECKPOINT)
        if artifact:
            for name, value in self.read(artifact, ("data.json", "state.json", "inventory.json")).items():
                write_json(Path(root) / "reports" / name, value)
        return artifact


def state_at(state, repository):
    return state.get("updated_at", {}).get(repository, "1970-01-01T00:00:00Z")


def accept_packet(state, packet, public):
    repository = repository_name(packet["repository"])
    if repository not in public:
        return []
    if any(row["repository"] != repository or row["visibility"] != "public" for row in packet["runs"]):
        raise ValueError("Repository result crosses its public scope")
    if any(not key.startswith(repository + ":") for key in packet["observations"]):
        raise ValueError("Repository observations cross their scope")
    if timestamp(packet["observed_at"]) >= timestamp(state_at(state, repository)):
        state["observations"] = {key: value for key, value in state["observations"].items() if not key.startswith(repository + ":")}
        state["observations"].update(packet["observations"])
        state.setdefault("updated_at", {})[repository] = packet["observed_at"]
    return packet["runs"]


def merge_result(root, packet, public):
    root = Path(root) / "reports"
    state = read_json(root / "state.json", {"schema_version": 1, "observations": {}, "updated_at": {}})
    accepted = accept_packet(state, packet, public)
    ledger = merge(read_json(root / "data.json", {"runs": []}), accepted, public_repositories=public)
    write_json(root / "data.json", ledger)
    write_json(root / "state.json", state)


def coordinate(root, repository="all", *, force=False, api=None, actions=None):
    api, actions = api or GitHub(), actions or Actions()
    actions.restore(root)
    inventory = api.repositories()
    if repository != "all" and repository not in {row["repository"] for row in inventory}:
        raise ValueError("Selected repository is not in the public inventory")
    observations = read_json(Path(root) / "reports/state.json", {"observations": {}})["observations"]
    selected = [row for row in inventory if repository in {"all", row["repository"]}]

    def changed(row):
        try:
            candidates = api.candidates(row["repository"], row["default_branch"])
            previous = {key for key in observations if key.startswith(row["repository"] + ":")}
            return force or bool(plan(candidates, observations)) or previous != {item["key"] for item in candidates}
        except APIError:
            # The repository worker records the unavailable discovery explicitly.
            return True

    dispatched, failed = [], []
    previous_inventory = read_json(Path(root) / "reports/inventory.json", None)
    publication_requested = previous_inventory is not None and previous_inventory["repositories"] != inventory
    if publication_requested:
        try:
            actions.dispatch("publish-report.yml", {})
        except APIError:
            failed.append("report-publication")
    with ThreadPoolExecutor(max_workers=8) as pool:
        pending = {pool.submit(changed, row): row["repository"] for row in selected}
        for future in as_completed(pending):
            name = pending[future]
            if future.result():
                try:
                    actions.dispatch("audit-repository.yml", {"repository": name, "force": str(force).lower()})
                    dispatched.append(name)
                    print("Dispatched " + name, flush=True)
                except APIError:
                    failed.append(name)
    return {"dispatched": dispatched, "incomplete": len(failed), "dispatch_failures": failed, "publication_requested": publication_requested}


def audit(root, repository, *, force=False, api=None, actions=None):
    repository_name(repository)
    if repository.split("/")[0] not in OWNERS:
        raise ValueError("Repository is outside the public inventory")
    api, actions = api or GitHub(), actions or Actions()
    root = Path(root)
    actions.restore(root)
    latest = actions.latest(result_name(repository))
    if latest:
        merge_result(root, actions.read(latest, ("result.json",))["result.json"], {repository})
    result = run(root, repository=repository, watch=not force, api=api, render_html=False)
    state = read_json(root / "reports/state.json", None)
    ledger = read_json(root / "reports/data.json", None)
    packet = {"repository": repository, "observed_at": state_at(state, repository),
              "observations": {key: head for key, head in state["observations"].items() if key.startswith(repository + ":")},
              "runs": [row for row in ledger["runs"] if row["repository"] == repository]}
    write_json(root / "out/result/result.json", packet)
    return result


def assemble(root, *, api=None, actions=None, event=None):
    """Reconcile durable results, including any completion event missed during outages."""
    api, actions = api or GitHub(), actions or Actions()
    root = Path(root)
    actions.restore(root)
    inventory = api.repositories()
    public = {row["repository"] for row in inventory}
    previous_ledger = read_json(root / "reports/data.json", {"runs": []})
    previous_inventory = read_json(root / "reports/inventory.json", {"repositories": []})["repositories"]
    state = read_json(root / "reports/state.json", {"schema_version": 1, "observations": {}})
    consumed = state.get("consumed_artifacts", {})
    latest = {}
    incoming = []
    source_run_id = (event or {}).get("inputs", {}).get("source_run_id")
    run_event = actions.worker_completion(source_run_id) if source_run_id else {}
    consumed_runs = state.get("consumed_workflow_runs", {})
    # One publisher coalesces a burst of independently completed repositories.
    # Queued events already represented in its checkpoint need no archive walk.
    if (run_event and run_event["id"] in consumed_runs.values() and previous_inventory == inventory
            and merge(previous_ledger, [], public_repositories=public)["runs"] == previous_ledger["runs"]):
        return {"changed": False, "repositories": len(public), "retained_runs": len(previous_ledger["runs"])}
    for artifact in actions.artifacts():
        name = artifact["name"]
        if name.startswith(RESULT_PREFIX) and (name not in latest or (artifact["created_at"], artifact["id"]) > (latest[name]["created_at"], latest[name]["id"])):
            latest[name] = artifact
    with ThreadPoolExecutor(max_workers=8) as pool:
        pending = {pool.submit(actions.read, artifact, ("result.json",)): artifact for artifact in latest.values() if consumed.get(artifact["name"]) != artifact["id"]}
        for future in as_completed(pending):
            artifact = pending[future]
            packet = future.result()["result.json"]
            if result_name(packet["repository"]) != artifact["name"]:
                raise ValueError("Artifact identity differs from its repository result")
            incoming.extend(accept_packet(state, packet, public))
            consumed[artifact["name"]] = artifact["id"]
            run_id = artifact.get("workflow_run", {}).get("id")
            if type(run_id) is int:
                consumed_runs[artifact["name"]] = run_id
    failures = []
    if run_event and run_event.get("conclusion") != "success" and not any(row.get("workflow_run", {}).get("id") == run_event["id"] for row in latest.values()):
        name = run_event.get("display_title", "").removeprefix("Audit repository · ")
        if name in public:
            failure = failed_result(name, None, "workflow", "repository_workflow_failed")
            failure.update(id="workflow:" + str(run_event["id"]) + ":" + str(run_event.get("run_attempt", 1)), finished_at=run_event["updated_at"])
            failures.append(failure)
    if run_event and not pending and not failures and previous_inventory == inventory and merge(previous_ledger, [], public_repositories=public)["runs"] == previous_ledger["runs"]:
        return {"changed": False, "repositories": len(public), "retained_runs": len(previous_ledger["runs"])}
    ledger = publish(root / "reports", incoming + failures, inventory=public)
    state["observations"] = {key: head for key, head in state["observations"].items() if key.split(":", 1)[0] in public}
    state["updated_at"] = {key: value for key, value in state.get("updated_at", {}).items() if key in public}
    state["consumed_artifacts"] = {key: value for key, value in consumed.items() if key in {result_name(name) for name in public}}
    state["consumed_workflow_runs"] = {key: value for key, value in consumed_runs.items() if key in state["consumed_artifacts"]}
    state["observed_at"] = utc_now()
    write_json(root / "reports/state.json", state)
    write_json(root / "reports/inventory.json", {"schema_version": 1, "repositories": inventory})
    return {"changed": True, "repositories": len(public), "retained_runs": len(ledger["runs"])}
