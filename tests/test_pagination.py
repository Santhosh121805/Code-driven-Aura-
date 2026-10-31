"""All five pagination types, including max_pages limits."""
import httpx
import pytest

from integration_platform.engine import EngineError, fetch_records
from tests.conftest import load, no_sleep, okta_config, only


def first(cfg):
    return cfg.streams[0]


async def test_cursor_next_token_follows_until_absent(cloudtrail):
    cfg = load("aws_cloudtrail")
    records, stats = await fetch_records(cfg, first(cfg), transport=cloudtrail, sleep=no_sleep)
    assert stats.pages == 3 and len(records) == 12


async def test_cursor_respects_max_pages(cloudtrail):
    cfg = load("aws_cloudtrail", stream={"pagination": {"type": "cursor", "cursor_path": "NextToken", "cursor_param": "NextToken", "max_pages": 2}})
    _, stats = await fetch_records(cfg, first(cfg), transport=cloudtrail, sleep=no_sleep)
    assert stats.pages == 2


async def test_page_number_stops_at_total_pages(firewall):
    cfg = only("acme_firewall", "logs")
    records, stats = await fetch_records(cfg, first(cfg), transport=firewall, sleep=no_sleep)
    assert stats.pages == 3 and len(records) == 12


async def test_page_number_devices_stream(firewall):
    cfg = only("acme_firewall", "devices")
    records, stats = await fetch_records(cfg, first(cfg), transport=firewall, sleep=no_sleep)
    assert stats.pages == 3 and len(records) == 15


async def test_page_number_without_total_stops_on_empty_page(firewall):
    cfg = only("acme_firewall", "logs", pagination={"type": "page", "page_size": 4, "max_pages": 10})
    records, stats = await fetch_records(cfg, first(cfg), transport=firewall, sleep=no_sleep)
    assert stats.pages == 4 and len(records) == 12


async def test_page_number_respects_max_pages(firewall):
    cfg = only("acme_firewall", "logs", pagination={"type": "page", "page_size": 4, "total_pages_path": "total_pages", "max_pages": 1})
    _, stats = await fetch_records(cfg, first(cfg), transport=firewall, sleep=no_sleep)
    assert stats.pages == 1


async def test_link_header_follows_next_until_absent(okta):
    cfg = okta_config()
    records, stats = await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)
    assert stats.pages == 3 and len(records) == 24


async def test_link_users_stream(okta):
    cfg = only("mock_okta", "users")
    records, stats = await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)
    assert stats.pages == 2 and len(records) == 10  # 5 per page


async def test_link_respects_max_pages(okta):
    cfg = okta_config(stream={"pagination": {"type": "link", "max_pages": 2}})
    records, stats = await fetch_records(cfg, first(cfg), transport=okta, sleep=no_sleep)
    assert stats.pages == 2 and len(records) == 20


async def test_link_stops_on_empty_page_even_with_next_link():
    """Okta's System Log keeps returning a next link while polling; an empty page must end the run."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        body = [{"uuid": "a"}] if calls["n"] == 1 else []
        return httpx.Response(200, json=body, headers={"Link": '<http://localhost:9003/api/v1/logs?after=x>; rel="next"'})
    cfg = okta_config(auth={"type": "none"})
    records, stats = await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert stats.pages == 2 and len(records) == 1


async def test_link_from_body_path():
    pages = {"/items": {"items": [{"id": 1}], "links": {"next": "/items?p=2"}}, "/items?p=2": {"items": [{"id": 2}], "links": {}}}

    def handler(request: httpx.Request) -> httpx.Response:
        key = request.url.path + (f"?{request.url.query.decode()}" if request.url.query else "")
        return httpx.Response(200, json=pages[key])
    cfg = only("acme_firewall", "logs", endpoint="/items", records_path="items",
               pagination={"type": "link", "next_path": "links.next"}, mapping={"id": "id"})
    records, stats = await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert [r["id"] for r in records] == [1, 2] and stats.pages == 2


async def test_link_to_another_host_is_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"uuid": "a"}], headers={"Link": '<https://attacker.example/steal>; rel="next"'})
    cfg = okta_config(auth={"type": "none"})
    with pytest.raises(EngineError, match="another host"):
        await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(handler), sleep=no_sleep)


def offset_handler(total: int, list_key: str | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.params
        offset = int(p.get("offset", p.get("startAt", p.get("startIndex", 0))))
        limit = int(p.get("limit", p.get("maxResults", p.get("resultsPerPage", 10))))
        items = [{"id": i} for i in range(offset, min(offset + limit, total))]
        return httpx.Response(200, json={list_key: items, "totalResults": total} if list_key else items)
    return handler


async def test_offset_pagination_stops_on_short_page():
    cfg = only("acme_firewall", "logs", records_path=None, pagination={"type": "offset", "limit": 10}, mapping={"id": "id"})
    records, stats = await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(offset_handler(24)), sleep=no_sleep)
    assert stats.pages == 3 and len(records) == 24


async def test_offset_pagination_jira_style_startat():
    cfg = load("jira", base_url="https://example.atlassian.net", auth={"type": "none"})
    stream = cfg.stream("users")
    records, stats = await fetch_records(cfg, stream, transport=httpx.MockTransport(offset_handler(120)), sleep=no_sleep)
    assert stats.pages == 3 and len(records) == 120  # 50 + 50 + 20


async def test_offset_pagination_nvd_style_total_results():
    """NVD: startIndex/resultsPerPage, stop when totalResults is reached (no extra empty request)."""
    calls = {"n": 0}
    inner = offset_handler(2500, "vulnerabilities")

    def handler(request):
        calls["n"] += 1
        return inner(request)
    cfg = load("nvd")
    records, stats = await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(handler), sleep=no_sleep)
    assert stats.pages == 3 and calls["n"] == 3 and len(records) == 2500  # 1000 + 1000 + 500


async def test_offset_respects_max_pages():
    cfg = only("acme_firewall", "logs", records_path=None, pagination={"type": "offset", "limit": 5, "max_pages": 2}, mapping={"id": "id"})
    records, stats = await fetch_records(cfg, first(cfg), transport=httpx.MockTransport(offset_handler(24)), sleep=no_sleep)
    assert stats.pages == 2 and len(records) == 10


async def test_none_single_request(cloudtrail):
    cfg = load("aws_cloudtrail", stream={"pagination": {"type": "none"}})
    records, stats = await fetch_records(cfg, first(cfg), transport=cloudtrail, sleep=no_sleep)
    assert stats.pages == 1 and len(records) == 4
