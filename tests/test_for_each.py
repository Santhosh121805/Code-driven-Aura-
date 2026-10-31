"""for_each fan-out: a stream runs once per record of another stream (parents first), a bounded number at a time,
with per-item 403/404 skipped, rate limits shared, parent-only sandboxed templating, and merge into the parent."""
import asyncio
import base64
import json

import httpx
import pytest

from integration_platform.config import ConfigError, validate_integration
from integration_platform.engine import dry_run_integration, fetch_sample, run_integration
from tests.conftest import SleepRecorder, no_sleep

REPOS = [{"id": i, "full_name": f"octo/repo{i}", "html_url": f"https://github.example.test/octo/repo{i}",
          "description": "" if i % 2 else f"Repo {i}", "topics": ["security"] if i == 1 else [], "language": "Python",
          "fork": False, "archived": False, "visibility": "public", "stargazers_count": i, "pushed_at": f"2026-10-0{i}T10:00:00Z"}
         for i in range(1, 7)]
README = "# repo1\n[![ci](https://x/b.svg)](https://x)\n\nScans **repositories** for leaked secrets.\n"


def config(**overrides):
    data = {
        "name": "repos", "display_name": "Repos", "base_url": "https://api.example.test", "auth": {"type": "none"},
        "streams": [
            {"name": "alerts", "entity": "event", "path": "/repos/{{ repo.full_name }}/alerts",
             "for_each": {"stream": "repositories", "as": "repo", "concurrency": 2},
             "parent_status": {"field": "dependabot_status", "ok": "enabled", "by_status": {403: "disabled", 404: "no access"}},
             "mapping": {"id": "join('#', [parent().full_name, to_string(number)])", "severity": "severity", "timestamp": "created_at",
                         "description": "summary", "resource": "parent().full_name"}},
            {"name": "repositories", "entity": "repository", "path": "/user/repos",
             "mapping": {"id": "id", "full_name": "full_name", "url": "html_url", "description": "description", "topics": "topics",
                         "primary_language": "language", "is_fork": "fork", "stars": "stargazers_count", "last_pushed_at": "pushed_at"}},
            {"name": "languages", "entity": "repository", "path": "/repos/{{ repo.full_name }}/languages",
             "for_each": {"stream": "repositories", "as": "repo"}, "merge_into_parent": True,
             "mapping": {"languages": "percent_map(@)"}},
            {"name": "readme", "entity": "repository", "path": "/repos/{{ repo.full_name }}/readme",
             "for_each": {"stream": "repositories", "as": "repo", "where": "!description"}, "merge_into_parent": True,
             "mapping": {"summary": "first_paragraph(base64_decode(content), `200`)",
                         "summary_source": "first_paragraph(base64_decode(content), `200`) && 'README'"}},
        ],
    }
    for k, v in overrides.items():
        data[k] = v
    return validate_integration(data)


class Api:
    """Fake API: repo3 has alerts disabled (403), repo5 is not visible (404); readme only for repo1."""

    def __init__(self, delay=0.0, rate_limit_once=None):
        self.calls, self.in_flight, self.peak = [], 0, 0
        self.delay, self.rate_limit_once = delay, rate_limit_once

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(path)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            await asyncio.sleep(self.delay)
            if path == self.rate_limit_once:
                self.rate_limit_once = None
                return httpx.Response(429, headers={"Retry-After": "7"})
            if path == "/user/repos":
                return httpx.Response(200, json=REPOS)
            repo = path.split("/")[3]
            if path.endswith("/alerts"):
                if repo == "repo3":
                    return httpx.Response(403, json={"message": "Dependabot alerts are disabled for this repository."})
                if repo == "repo5":
                    return httpx.Response(404, json={"message": "Not Found"})
                n = int(repo[-1])
                return httpx.Response(200, json=[{"number": k, "severity": "critical" if k == 1 else "low", "created_at": "2026-10-30T00:00:00Z",
                                                  "summary": f"{repo} advisory {k}"} for k in range(1, n % 3 + 2)])
            if path.endswith("/languages"):
                return httpx.Response(200, json={"Python": 900, "Shell": 100})
            if path.endswith("/readme"):
                if repo != "repo1":
                    return httpx.Response(404, json={"message": "Not Found"})
                return httpx.Response(200, json={"content": base64.b64encode(README.encode()).decode(), "encoding": "base64"})
            return httpx.Response(404, json={"message": "Not Found"})
        finally:
            self.in_flight -= 1


async def test_parents_run_first_and_children_fan_out_per_record(db):
    api = Api()
    result = await run_integration(config(), db, transport=httpx.MockTransport(api), sleep=no_sleep)
    assert [s["name"] for s in result["streams"]] == ["repositories", "alerts", "languages", "readme"]  # parent first
    assert result["status"] == "success"
    alerts = next(s for s in result["streams"] if s["name"] == "alerts")
    assert (alerts["items"], alerts["eligible"], alerts["skipped"]) == (6, 6, 2)
    events, _ = db.list_records("event", "repos")
    assert {e["resource"] for e in events} == {"octo/repo1", "octo/repo2", "octo/repo4", "octo/repo6"}
    assert all(e["id"].startswith(e["resource"] + "#") for e in events)


async def test_per_item_403_404_are_recorded_and_skipped_with_reasons(db):
    result = await run_integration(config(), db, transport=httpx.MockTransport(Api()), sleep=no_sleep)
    alerts = next(s for s in result["streams"] if s["name"] == "alerts")
    assert alerts["status"] == "ok" and result["skipped_items"] == 2 + 2  # 2 alert repos + 2 readme 404s
    assert alerts["skipped_reasons"] == {"HTTP 403: Dependabot alerts are disabled for this repository.": 1, "HTTP 404: Not Found": 1}
    assert {s["item"] for s in alerts["skipped_items"]} == {"/repos/octo/repo3/alerts", "/repos/octo/repo5/alerts"}
    assert "2 item(s) skipped" in alerts["note"]
    run = db.recent_runs("repos")[0]
    assert run["status"] == "success" and run["detail"]["skipped_items"] == 4


async def test_parent_status_merge_and_readme_summary(db):
    await run_integration(config(), db, transport=httpx.MockTransport(Api()), sleep=no_sleep)
    repos = {r["full_name"]: r for r in db.list_records("repository", "repos", limit=50)[0]}
    assert len(repos) == 6
    assert [repos[f"octo/repo{i}"]["dependabot_status"] for i in range(1, 7)] == \
        ["enabled", "enabled", "disabled", "enabled", "no access", "enabled"]
    assert repos["octo/repo2"]["languages"] == {"Python": {"bytes": 900, "percent": 90.0}, "Shell": {"bytes": 100, "percent": 10.0}}
    assert repos["octo/repo1"]["summary"] == "Scans repositories for leaked secrets." and repos["octo/repo1"]["summary_source"] == "README"
    assert repos["octo/repo1"]["topics"] == ["security"]
    assert repos["octo/repo2"]["summary"] is None  # has a description: README not fetched


async def test_readme_only_for_repos_without_description(db):
    api = Api()
    await run_integration(config(), db, transport=httpx.MockTransport(api), sleep=no_sleep)
    assert sorted(p for p in api.calls if p.endswith("/readme")) == [f"/repos/octo/repo{i}/readme" for i in (1, 3, 5)]


async def test_rerun_keeps_merged_fields(db):
    for _ in range(2):
        await run_integration(config(), db, transport=httpx.MockTransport(Api()), sleep=no_sleep)
    repo = next(r for r in db.list_records("repository", "repos", limit=50)[0] if r["full_name"] == "octo/repo1")
    assert repo["languages"] and repo["summary"] and repo["dependabot_status"] == "enabled"


async def test_concurrency_is_bounded(db):
    api = Api(delay=0.02)
    cfg = config()
    await run_integration(cfg, db, transport=httpx.MockTransport(api), sleep=no_sleep)
    # streams run one after another; inside one stream at most for_each.concurrency requests are in flight
    assert api.peak == 4  # languages: default concurrency 4
    api2 = Api(delay=0.02)
    only_alerts = config(streams=[s.model_dump(mode="json", exclude_none=True) for s in cfg.streams if s.name in ("repositories", "alerts")])
    await run_integration(only_alerts, db, transport=httpx.MockTransport(api2), sleep=no_sleep)
    assert api2.peak == 2  # alerts: concurrency 2


async def test_rate_limit_retry_after_applies_inside_fan_out(db):
    rec = SleepRecorder()
    api = Api(rate_limit_once="/repos/octo/repo2/languages")
    result = await run_integration(config(), db, transport=httpx.MockTransport(api), sleep=rec)
    assert result["status"] == "success" and 7 in rec.delays
    assert "HTTP 429: waited 7s due to Retry-After" in result["retry_log"]
    assert api.calls.count("/repos/octo/repo2/languages") == 2  # retried once, not skipped


async def test_401_on_an_item_fails_the_stream_not_skipped(db):
    def handler(request):
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=REPOS)
        return httpx.Response(401, json={"message": "Bad credentials"})
    result = await run_integration(config(), db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    alerts = next(s for s in result["streams"] if s["name"] == "alerts")
    assert alerts["status"] == "error" and "HTTP 401" in alerts["error"]
    assert result["status"] == "partial"
    assert all(s["status"] == "not run" for s in result["streams"] if s["name"] in ("languages", "readme"))


async def test_children_skip_when_the_parent_fails(db):
    def handler(request):
        return httpx.Response(404, json={"message": "Not Found"})
    result = await run_integration(config(), db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert [s["status"] for s in result["streams"][1:]] == ["skipped: repositories did not run"] * 3


async def test_template_values_are_url_quoted_and_settings_never_expand(db, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "s3cr3t")
    repos = [{"id": 1, "full_name": "octo/a b?x=1#frag"}, {"id": 2, "full_name": "${SECRET_TOKEN}"}, {"id": 3, "full_name": "octo/../admin"}]
    seen = []

    def handler(request):
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=repos)
        seen.append(request.url.raw_path.decode())
        return httpx.Response(200, json={"Python": 1})
    cfg = config(streams=[s.model_dump(mode="json", exclude_none=True) for s in config().streams if s.name in ("repositories", "languages")])
    result = await run_integration(cfg, db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert "/repos/octo/a%20b%3Fx%3D1%23frag/languages" in seen
    assert not any("s3cr3t" in p for p in seen)  # a parent value is never resolved as a ${SETTING}
    langs = next(s for s in result["streams"] if s["name"] == "languages")
    assert any("relative segments" in s["reason"] for s in langs["skipped_items"])  # ../ refused


def test_templating_only_allows_the_parent_record():
    base = config().model_dump(mode="json", exclude_none=True)
    bad = json.loads(json.dumps(base))
    bad["streams"][2]["path"] = "/repos/{{ repo.full_name }}/{{ config.secret }}"
    del bad["streams"][2]["endpoint"]
    with pytest.raises(ConfigError, match="only {{ repo.<field> }} is available"):
        validate_integration(bad)
    no_fan = json.loads(json.dumps(base))
    no_fan["streams"][1]["endpoint"] = "/user/{{ repo.full_name }}"
    with pytest.raises(ConfigError, match="placeholders need for_each"):
        validate_integration(no_fan)


def test_for_each_validation():
    base = config().model_dump(mode="json", exclude_none=True)
    for mutate, message in [
        (lambda d: d["streams"][0]["for_each"].update(stream="nope"), "must be another stream"),
        (lambda d: d["streams"][0]["for_each"].update(stream="alerts"), "must be another stream"),
        (lambda d: d["streams"][2].update(entity="event", mapping={"id": "x", "timestamp": "y"}), "merge_into_parent needs entity repository"),
        (lambda d: d["streams"][0]["parent_status"].update(field="colour"), "not a repository field"),
        (lambda d: d["streams"][1].pop("mapping").pop("full_name") and d["streams"][1].update(mapping={"id": "id"}), "needs full_name mapped"),
    ]:
        data = json.loads(json.dumps(base))
        mutate(data)
        with pytest.raises(ConfigError, match=message):
            validate_integration(data)
    data = json.loads(json.dumps(base))
    data["streams"][1]["for_each"] = {"stream": "languages", "as": "x"}  # repositories <-> languages
    with pytest.raises(ConfigError, match="cycle|must be another"):
        validate_integration(data)


def test_yaml_round_trip_keeps_as_and_path_alias():
    from integration_platform.config import parse_yaml, to_yaml
    cfg = config()
    text = to_yaml(cfg)
    assert "as: repo" in text and "as_" not in text
    assert validate_integration(parse_yaml(text)) == cfg


async def test_dry_run_and_sample_use_the_first_parent_records():
    api = Api()
    result = await dry_run_integration(config(), transport=httpx.MockTransport(api))
    alerts = next(s for s in result["streams"] if s["name"] == "alerts")
    assert alerts["status"] == "ok" and alerts["items"] == 3 and alerts["normalised"][0]["resource"] == "octo/repo1"
    body, _ = await fetch_sample(config(), 0, transport=httpx.MockTransport(Api()))  # alerts: runs for repo1
    assert body[0]["summary"] == "repo1 advisory 1"


async def test_endpoint_change_relearns_the_guard_baseline(db):
    from integration_platform.config import validate_integration as v
    small = config(streams=[s.model_dump(mode="json", exclude_none=True) for s in config().streams if s.name == "repositories"],
                   exfiltration_guard={"min_records": 5, "multiplier": 2, "min_baseline_runs": 2})
    for _ in range(2):
        await run_integration(small, db, transport=httpx.MockTransport(Api()), sleep=no_sleep)
    big = v({**small.model_dump(mode="json", exclude_none=True), "streams": [s.model_dump(mode="json", exclude_none=True) for s in config().streams]})
    result = await run_integration(big, db, transport=httpx.MockTransport(Api()), sleep=no_sleep)
    assert result["status"] == "success" and result["suspicious"] is None  # more endpoints != stolen token


async def test_parent_status_by_reason_wins_over_status_code(db):
    def handler(request):
        if request.url.path == "/user/repos":
            return httpx.Response(200, json=REPOS[:2])
        return httpx.Response(403, json={"message": "Resource not accessible by personal access token"})
    data = config().model_dump(mode="json", exclude_none=True)
    data["streams"] = [s for s in data["streams"] if s["name"] in ("repositories", "alerts")]
    data["streams"][0]["parent_status"]["by_reason"] = {"Not Accessible": "no access"}  # case-insensitive substring
    await run_integration(validate_integration(data), db, transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert {r["dependabot_status"] for r in db.list_records("repository", "repos")[0]} == {"no access"}


@pytest.mark.parametrize("readme,summary", [
    ("# App\n\n## Project info\n\n**URL**: https://lovable.dev/projects/abc\n\n## How can I edit this code?\n\nThere are several ways of editing your application.\n", None),
    ("TODO: Document your project here\n", None),
    ("---\ntitle: MedTriage\nemoji: x\nsdk: docker\n---\n\n# MedTriage\n\nA benchmark that triages patient messages by urgency.\n",
     "A benchmark that triages patient messages by urgency."),
    ("# X\n\nOverview · Architecture · Pipeline · Features\n\n- one feature item here\n\nA platform that matches donors to patients in real time.\n",
     "A platform that matches donors to patients in real time."),
    ("# X\n\n- Smart matching: pairs donors and patients\n- SOS alerts\n", "- Smart matching: pairs donors and patients - SOS alerts"),
    ("# X\n\n" + "word " * 80, ("word " * 80).strip()[:200].rsplit(" ", 1)[0] + "…"),
])
def test_readme_summary_skips_boilerplate(readme, summary):
    from integration_platform.normaliser import first_paragraph
    assert first_paragraph(readme, 200) == summary
