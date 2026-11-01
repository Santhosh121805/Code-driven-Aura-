"""AI mapping assistant per entity: rule-based fallback, verification of LLM output, masking, detection."""
import json

from integration_platform import ai_mapper
from integration_platform.ai_mapper import detect_pagination, detect_records_path, mask, suggest_mapping, verify_suggestion
from tests.fakes import mock_firewall, mock_okta
from tests.conftest import ROOT

OKTA_SAMPLE = [
    {"uuid": "7d864e71-870b-774d-67e1-444c0a1b2c3d", "published": "2026-10-31T06:19:08.123Z", "eventType": "user.mfa.factor.reset_all",
     "version": "0", "severity": "ERROR", "displayMessage": "Reset all factors for user",
     "actor": {"id": "00u1a2b3c4d5e6f7g8h", "type": "User", "alternateId": "svc.backup@mitigata-demo.in", "displayName": "Svc Backup"},
     "client": {"ipAddress": "45.155.205.233", "geographicalContext": {"country": "India", "city": "Mumbai"}},
     "outcome": {"result": "SUCCESS", "reason": None}, "transaction": {"type": "WEB", "id": "a1b2c3d4e5f6a7b8c9d0"}},
    {"uuid": "03f97310-7283-49ca-f18b-e188aa00bb11", "published": "2026-10-31T06:18:12.456Z", "eventType": "user.session.start",
     "version": "0", "severity": "WARN", "displayMessage": "User login to Okta",
     "actor": {"id": "00u9z8y7x6w5v4u3t2s", "type": "User", "alternateId": "kavya.iyer@mitigata-demo.in", "displayName": "Kavya Iyer"},
     "client": {"ipAddress": "10.12.84.158", "geographicalContext": {"country": "India", "city": "Pune"}},
     "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"}, "transaction": {"type": "WEB", "id": "f0e1d2c3b4a596877869"}},
    {"uuid": "9a8b7c6d-5e4f-3a2b-1c0d-ffeeddccbbaa", "published": "2026-10-31T06:17:00.000Z", "eventType": "user.session.start",
     "version": "0", "severity": "INFO", "displayMessage": "User login to Okta",
     "actor": {"id": "00u0q1w2e3r4t5y6u7i", "type": "User", "alternateId": "rahul.verma@mitigata-demo.in", "displayName": "Rahul Verma"},
     "client": {"ipAddress": "192.168.4.20", "geographicalContext": {"country": "India", "city": "Chennai"}},
     "outcome": {"result": "SUCCESS", "reason": None}, "transaction": {"type": "WEB", "id": "0011223344556677aabb"}},
]
CLOUDTRAIL_SAMPLE = {"Records": [
    {"eventVersion": "1.08", "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE1", "arn": "arn:aws:iam::491085362710:user/it.admin",
                                              "accountId": "491085362710", "userName": "it.admin"},
     "eventTime": "2026-10-31T05:49:32Z", "eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging", "awsRegion": "ap-south-1",
     "sourceIPAddress": "45.155.205.233", "userAgent": "aws-cli/2.15.30", "requestID": "r-1", "eventID": "11111111-2222-3333-4444-555555555555",
     "readOnly": False, "eventType": "AwsApiCall", "recipientAccountId": "491085362710"},
    {"eventVersion": "1.08", "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE2", "arn": "arn:aws:iam::491085362710:user/priya.sharma",
                                              "accountId": "491085362710", "userName": "priya.sharma"},
     "eventTime": "2026-10-31T05:49:46Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "awsRegion": "ap-south-1",
     "sourceIPAddress": "10.0.4.23", "userAgent": "aws-cli/2.15.30", "requestID": "r-2", "eventID": "66666666-7777-8888-9999-000000000000",
     "readOnly": True, "eventType": "AwsApiCall", "recipientAccountId": "491085362710"},
], "NextToken": "eyJwYWdlIjogMn0="}


def test_events_from_okta_sample():
    r = suggest_mapping(OKTA_SAMPLE, "event", link_header=True)
    assert r["engine"] == "Rule-based fallback" and "No LLM configured" in r["fallback_reason"]
    assert r["records_path"] is None and r["entity"] == "event"
    assert r["mapping"] == {"id": "uuid", "type": "eventType", "severity": "severity", "timestamp": "published",
                            "description": "displayMessage", "src_ip": "client.ipAddress", "user": "actor.alternateId"}
    assert r["severity_map"] == {"ERROR": "critical", "WARN": "medium", "INFO": "info", "DEBUG": "info"}
    assert r["pagination_hint"]["type"] == "link"


def test_users_from_okta_style_sample_joins_first_and_last_name():
    r = suggest_mapping([mock_okta.user(i) for i in range(5)], "user", link_header=True)
    assert r["mapping"] == {"id": "id", "name": "join(' ', [profile.firstName || '', profile.lastName || ''])",
                            "email": "profile.email", "status": "status", "last_login": "lastLogin"}
    assert r["time_format"] == "iso8601"


def test_devices_from_firewall_inventory_sample():
    r = suggest_mapping({"results": [mock_firewall.device(i) for i in range(5)], "page": 1, "total_pages": 3}, "device")
    assert r["records_path"] == "results"
    m = r["mapping"]
    assert (m["id"], m["hostname"], m["ip"], m["owner"], m["last_seen"]) == ("mac", "hostname", "ipv4_address", "user", "last_seen")
    assert m["os"].startswith("os_") and r["time_format"] == "epoch_s"
    assert r["pagination_hint"]["type"] == "page"


def test_cisa_kev_live_add_suggestion():
    kev = json.loads((ROOT / "tests/fakes/data/kev.json").read_text(encoding="utf-8"))
    kev["vulnerabilities"] = kev["vulnerabilities"][:20]
    r = suggest_mapping(kev, "event")
    assert r["records_path"] == "vulnerabilities"
    assert r["mapping"] == {"id": "cveID", "type": "'vulnerability'", "timestamp": "dateAdded", "description": "vulnerabilityName"}
    assert r["default_severity"] == "high" and r["time_format"] == "iso8601"


def test_top_level_list_without_link_header_hints_offset():
    assert suggest_mapping(OKTA_SAMPLE)["pagination_hint"]["type"] == "offset"


def test_heuristic_on_nested_cloudtrail_sample():
    r = suggest_mapping(CLOUDTRAIL_SAMPLE, "event")
    m = r["mapping"]
    assert r["records_path"] == "Records"
    assert (m["id"], m["timestamp"], m["src_ip"]) == ("eventID", "eventTime", "sourceIPAddress")
    assert m["user"].startswith("userIdentity.") and "userAgent" not in m.values()
    assert r["pagination_hint"]["type"] == "cursor" and r["pagination_hint"]["cursor_path"] == "NextToken"


def test_severity_families_pick_best_overlap():
    assert ai_mapper.suggest_severity_map(["warn", "alert"]) == {"warn": "medium", "alert": "critical", "info": "info"}
    assert ai_mapper.suggest_severity_map([1, 4]) == {"1": "low", "2": "medium", "3": "high", "4": "critical"}
    assert ai_mapper.suggest_severity_map(["HIGH", "LOW"])["CRITICAL"] == "critical"


def test_verification_drops_fake_path_and_flags_type_mismatch():
    suggestion = {"records_path": "Records",
                  "mapping": {"host": "device.does_not_exist", "timestamp": "eventName", "description": "eventName", "colour": "x"},
                  "confidence": {"host": 0.9, "timestamp": 0.9, "description": 0.95}}
    v = verify_suggestion(suggestion, CLOUDTRAIL_SAMPLE, "Records", "event")
    assert v["fields"]["host"]["status"] == "needs_manual" and v["fields"]["host"]["path"] == ""
    assert v["fields"]["timestamp"]["status"] == "needs_manual" and v["fields"]["timestamp"]["path"] == ""  # unreadable time: dropped
    assert v["fields"]["description"]["status"] == "ok" and v["fields"]["description"]["confidence"] == 0.95
    assert "colour" not in v["fields"]


def test_values_the_normaliser_would_reject_are_never_suggested():
    """Real case: the AI mapped KEV's cwes (a list) to resource and vendorProject to src_ip; every record was quarantined."""
    sample = {"vulnerabilities": [{"cveID": "CVE-2024-1", "dateAdded": "2024-05-01", "vendorProject": "Acme", "cwes": ["CWE-79"],
                                   "shortDescription": "XSS in Acme portal"}]}
    v = verify_suggestion({"records_path": "vulnerabilities", "mapping": {"id": "cveID", "timestamp": "dateAdded", "resource": "cwes",
                                                                         "src_ip": "vendorProject", "description": "shortDescription"}},
                          sample, "vulnerabilities", "event")
    assert v["fields"]["resource"]["status"] == "needs_manual" and v["fields"]["src_ip"]["status"] == "needs_manual"
    assert {f for f, e in v["fields"].items() if e["status"] == "ok"} == {"id", "timestamp", "description"}
    rules = suggest_mapping(sample, "event", use_llm=False)["mapping"]
    assert "cwes" not in rules.values()  # the rule-based fallback skips lists too
    repo = verify_suggestion({"mapping": {"topics": "tags"}}, [{"tags": ["a", "b"]}], None, "repository")
    assert repo["fields"]["topics"]["status"] == "ok"  # list fields (topics, languages) still take lists


def test_verification_rejects_fields_from_another_entity():
    v = verify_suggestion({"mapping": {"hostname": "eventName", "description": "eventName"}}, CLOUDTRAIL_SAMPLE, "Records", "event")
    assert "hostname" not in v["fields"] and "description" in v["fields"]


def test_bad_records_path_from_llm_falls_back_to_detected():
    v = verify_suggestion({"records_path": "Nope", "mapping": {"description": "eventName"}}, CLOUDTRAIL_SAMPLE, "Records")
    assert v["records_path"] == "Records" and v["fields"]["description"]["status"] == "ok"


def test_ai_path_verified_and_gaps_filled_by_rules(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    fake = {"records_path": None, "mapping": {"description": "eventType", "user": "actor.alternateId", "host": "hostname.fake"},
            "severity_map": {"ERROR": "critical", "WARN": "medium", "INFO": "bogus"}, "time_format": "iso8601",
            "confidence": {"description": 0.9, "user": 0.95, "host": 0.8}, "notes": "okta system log"}
    monkeypatch.setattr(ai_mapper, "call_llm", lambda *a: (fake, "anthropic/test-model"))
    r = suggest_mapping(OKTA_SAMPLE, "event")
    assert r["engine"] == "AI (anthropic/test-model)"
    fields = {f["field"]: f for f in r["fields"]}
    assert fields["description"]["source"] == "ai" and fields["description"]["path"] == "eventType"
    assert fields["host"]["status"] == "needs_manual"
    assert fields["id"]["source"] == "rules"
    assert r["severity_map"] == {"ERROR": "critical", "WARN": "medium"}


def test_llm_failure_falls_back(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    def boom(*a):
        raise TimeoutError("10 s timeout")
    monkeypatch.setattr(ai_mapper, "call_llm", boom)
    r = suggest_mapping(OKTA_SAMPLE, "event")
    assert r["engine"] == "Rule-based fallback" and "TimeoutError" in r["fallback_reason"]
    assert r["mapping"]["id"] == "uuid"


FAKE_SARVAM_KEY = "sk_fake_sarvam_test_key_0001"
SARVAM_JSON = {"records_path": None, "mapping": {"id": "uuid", "description": "displayMessage", "host": "hostname.fake"},
               "confidence": {"id": 0.95, "description": 0.9, "host": 0.8}, "notes": "okta system log"}
# What sarvam-105b can send: reasoning (with a brace of its own) and a code fence around the JSON answer.
SARVAM_REPLY = ("<think>Each record looks like {\"uuid\": ..., \"published\": ...}; uuid is the id.</think>\n"
                "Sure! Here is the mapping:\n```json\n" + json.dumps(SARVAM_JSON) + "\n```\nLet me know if you need changes.")


def sarvam(monkeypatch, *replies):
    """Point the OpenAI-compatible path at Sarvam and answer with `replies` (status, content) in order."""
    for k, v in {"LLM_BASE_URL": "https://api.sarvam.ai/v1", "LLM_MODEL": "sarvam-105b", "LLM_API_KEY": FAKE_SARVAM_KEY}.items():
        monkeypatch.setenv(k, v)
    calls, pending = [], list(replies)

    def post(url, headers, timeout, json):
        calls.append({"url": url, "headers": headers, "timeout": timeout,
                      "reasoning": (json.get("reasoning_effort", "unset"), json.get("max_tokens"))})
        status, content = pending.pop(0)
        message = {"role": "assistant", "content": content, "reasoning_content": '{"mapping": {"id": "from.reasoning"}}'}
        return ai_mapper.httpx.Response(status, json={"choices": [{"message": message}]}, request=ai_mapper.httpx.Request("POST", url))
    monkeypatch.setattr(ai_mapper.httpx, "post", post)
    return calls


def test_sarvam_reply_with_reasoning_around_json(monkeypatch, caplog):
    calls = sarvam(monkeypatch, (200, SARVAM_REPLY))
    r = suggest_mapping(OKTA_SAMPLE, "event")
    assert r["engine"] == "AI (Sarvam)"
    assert calls == [{"url": "https://api.sarvam.ai/v1/chat/completions", "headers": {"Authorization": f"Bearer {FAKE_SARVAM_KEY}"},
                      "timeout": 30.0, "reasoning": (None, 4096)}]
    fields = {f["field"]: f for f in r["fields"]}
    assert (fields["id"]["source"], fields["id"]["path"]) == ("ai", "uuid")    # from content, not reasoning_content
    assert fields["host"]["status"] == "needs_manual"                         # invalid path still dropped by verification
    assert (fields["user"]["source"], fields["user"]["path"]) == ("rules", "actor.alternateId")
    assert FAKE_SARVAM_KEY not in caplog.text


def test_sarvam_falls_back_to_subscription_key_header(monkeypatch):
    calls = sarvam(monkeypatch, (401, ""), (200, SARVAM_REPLY))
    assert suggest_mapping(OKTA_SAMPLE, "event")["engine"] == "AI (Sarvam)"
    assert [c["headers"] for c in calls] == [{"Authorization": f"Bearer {FAKE_SARVAM_KEY}"}, {"api-subscription-key": FAKE_SARVAM_KEY}]


def test_sarvam_reply_without_json_falls_back_to_rules(monkeypatch, caplog):
    sarvam(monkeypatch, (200, "<think>Thinking about the mapping...</think> I could not decide."))
    r = suggest_mapping(OKTA_SAMPLE, "event")
    assert r["engine"] == "Rule-based fallback" and "no JSON object" in r["fallback_reason"]
    assert r["mapping"]["id"] == "uuid"
    assert FAKE_SARVAM_KEY not in caplog.text + r["fallback_reason"]


def test_kev_ai_answer_with_empty_paths_and_free_text_severity(monkeypatch, caplog):
    """What sarvam-105b really answered for CISA KEV: "" for unmapped fields, severity on a free-text field."""
    kev = json.loads((ROOT / "tests/fakes/data/kev.json").read_text(encoding="utf-8"))
    kev["vulnerabilities"] = kev["vulnerabilities"][:20]
    answer = {"records_path": "vulnerabilities",
              "mapping": {"id": "cveID", "severity": "requiredAction", "timestamp": "dateAdded", "src_ip": "", "dst_ip": ""},
              "severity_map": {"Unknown": "info", "No": "low", "Yes": "high"}}
    sarvam(monkeypatch, (200, json.dumps(answer)))
    r = suggest_mapping(kev, "event")
    fields = {f["field"]: f for f in r["fields"]}
    assert r["engine"] == "AI (Sarvam)" and fields["id"]["source"] == "ai"
    assert fields["src_ip"]["note"] == "No matching field found"           # "" = not mapped, not "invalid JMESPath"
    assert "severity" not in r["mapping"] and r["default_severity"] == "high"
    assert r["severity_map"] == {}                                          # the AI map was for another field
    assert FAKE_SARVAM_KEY not in caplog.text


def test_masking_before_llm():
    masked = mask({"actor": {"alternateId": "kavya.iyer@mitigata-demo.in"}, "api_token": "short",
                   "session_blob": "x", "hash": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==", "host": "finance-pc-07",
                   "ts": "2026-10-31T05:49:32.123456Z"})
    assert masked["actor"]["alternateId"] == "user@example.com"
    assert masked["api_token"] == "<redacted-secret>" and masked["session_blob"] == "<redacted-secret>"
    assert masked["hash"] == "<redacted-token>"
    assert masked["host"] == "finance-pc-07" and masked["ts"] == "2026-10-31T05:49:32.123456Z"


def test_records_path_picks_largest_array():
    doc = {"meta": {"tags": [{"a": 1}]}, "results": [{"id": 1}, {"id": 2}, {"id": 3}]}
    assert detect_records_path(doc)[0] == "results"
    assert detect_pagination({"results": [], "page": 1, "total_pages": 3})["type"] == "page"
