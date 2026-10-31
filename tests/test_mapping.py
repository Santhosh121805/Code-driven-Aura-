"""FR-5 mapping + transforms per entity: rename fields, pick nested values, convert dates, severity maps."""
from integration_platform.config import Transforms
from integration_platform.normaliser import map_severity, normalise, parse_time
from tests.conftest import load, okta_config, only


def test_time_formats():
    assert parse_time("2026-10-31T05:49:32Z") == "2026-10-31T05:49:32Z"
    assert parse_time("2026-10-31T11:19:32+05:30") == "2026-10-31T05:49:32Z"  # IST -> UTC
    assert parse_time(1793425772, "epoch_s") == "2026-10-31T05:49:32Z"
    assert parse_time(1793425772000, "epoch_ms") == "2026-10-31T05:49:32Z"
    assert parse_time("1793425772", "epoch_s") == "2026-10-31T05:49:32Z"
    assert parse_time("2026-10-30") == "2026-10-30T00:00:00Z"  # date-only (CISA KEV dateAdded)
    assert parse_time("2026-10-31T05:49:32.123") == "2026-10-31T05:49:32Z"  # NVD lastModified (no zone = UTC)
    assert parse_time(1793425772000, "iso8601") == "2026-10-31T05:49:32Z"  # auto-detect fallback
    assert parse_time("not a date") is None


def test_severity_maps():
    numeric = Transforms(severity_map={"1": "low", "2": "medium", "3": "high", "4": "critical"})
    assert map_severity(4, numeric) == "critical" and map_severity("2", numeric) == "medium"
    upper = Transforms(severity_map={"LOW": "low", "CRITICAL": "critical"})
    assert map_severity("critical", upper) == "critical"
    assert map_severity("High", Transforms()) == "high"
    assert map_severity("weird", Transforms(default_severity="low")) == "low"
    assert map_severity(None, Transforms()) == "info"


def ct(**extra):
    base = {"eventID": "e-1", "eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com", "eventTime": "2026-10-31T05:49:32Z",
            "userIdentity": {"arn": "arn:aws:iam::491085362710:user/priya.sharma"}, "sourceIPAddress": "45.155.205.233", "responseElements": None}
    return {**base, **extra}


def test_event_from_cloudtrail_record_keeps_source_and_fetched_at():
    cfg = load("aws_cloudtrail")
    record = ct()
    row = normalise(record, cfg.streams[0], "aws_cloudtrail", "2026-10-31T06:00:00Z")
    assert row == {"id": "e-1", "type": "StopLogging", "severity": "critical", "timestamp": "2026-10-31T05:49:32Z",
                   "description": "StopLogging (cloudtrail.amazonaws.com)", "host": None, "src_ip": "45.155.205.233", "dst_ip": None,
                   "user": "arn:aws:iam::491085362710:user/priya.sharma", "resource": None, "source": "aws_cloudtrail", "stream": "events",
                   "entity": "event", "fetched_at": "2026-10-31T06:00:00Z", "raw": record}


def test_cloudtrail_severity_derived_from_event_name_and_outcome():
    cfg = load("aws_cloudtrail")
    sev = lambda **kw: normalise(ct(**kw), cfg.streams[0], "x")["severity"]  # noqa: E731
    assert sev(eventName="ConsoleLogin", responseElements={"ConsoleLogin": "Success"}) == "info"
    assert sev(eventName="ConsoleLogin", responseElements={"ConsoleLogin": "Failure"}) == "medium"
    assert sev(eventName="DeleteTrail") == "critical" and sev(eventName="StopLogging") == "critical"
    assert sev(eventName="PutBucketPolicy") == "high"
    assert sev(eventName="ListBuckets", errorCode="AccessDenied") == "medium"
    assert sev(eventName="SomethingNew") == "low"


def test_user_from_okta_style_record_joins_names_and_converts_dates():
    cfg = load("mock_okta")
    record = {"id": "00u1", "status": "ACTIVE", "lastLogin": "2026-10-30T18:28:43.000Z",
              "profile": {"firstName": "Priya", "lastName": "Sharma", "email": "priya.sharma@mitigata-demo.in"}}
    row = normalise(record, cfg.stream("users"), "mock_okta", "2026-10-31T06:00:00Z")
    assert {k: row[k] for k in ("id", "name", "email", "status", "last_login", "source", "fetched_at", "entity")} == {
        "id": "00u1", "name": "Priya Sharma", "email": "priya.sharma@mitigata-demo.in", "status": "ACTIVE",
        "last_login": "2026-10-30T18:28:43Z", "source": "mock_okta", "fetched_at": "2026-10-31T06:00:00Z", "entity": "user"}


def test_user_without_last_name_and_never_logged_in():
    cfg = load("mock_okta")
    row = normalise({"id": "00u2", "status": "PROVISIONED", "lastLogin": None, "profile": {"firstName": "Svc", "lastName": None}},
                    cfg.stream("users"), "mock_okta")
    assert row["name"] == "Svc " and row["last_login"] is None  # last_login is optional for users


def test_device_fills_every_field_with_epoch_conversion():
    cfg = only("acme_firewall", "devices")
    record = {"mac": "a6:01:ed:72:e2:0a", "hostname": "finance-pc-07", "ipv4_address": "10.17.114.228", "os_name": "Windows",
              "os_version": "11 23H2", "user": "arjun.mehta@mitigata-demo.in", "last_seen": 1793425772}
    row = normalise(record, cfg.streams[0], "acme_firewall", "2026-10-31T06:00:00Z")
    assert {k: row[k] for k in ("id", "hostname", "ip", "os", "owner", "last_seen", "source", "fetched_at")} == {
        "id": "a6:01:ed:72:e2:0a", "hostname": "finance-pc-07", "ip": "10.17.114.228", "os": "Windows 11 23H2",
        "owner": "arjun.mehta@mitigata-demo.in", "last_seen": "2026-10-31T05:49:32Z", "source": "acme_firewall",
        "fetched_at": "2026-10-31T06:00:00Z"}


def test_okta_event_nested_actor_and_ms_iso_time():
    record = {"uuid": "u-1", "published": "2026-10-31T05:49:32.123Z", "eventType": "user.mfa.factor.reset_all", "severity": "ERROR",
              "displayMessage": "Reset all factors for user", "actor": {"alternateId": "kavya.iyer@mitigata-demo.in"},
              "client": {"ipAddress": "45.155.205.233"}}
    row = normalise(record, okta_config().streams[0], "okta_wizard")
    assert (row["severity"], row["type"], row["description"], row["user"], row["src_ip"], row["timestamp"]) == (
        "critical", "user.mfa.factor.reset_all", "Reset all factors for user", "kavya.iyer@mitigata-demo.in", "45.155.205.233",
        "2026-10-31T05:49:32Z")


def test_nvd_record_severity_from_cvss_31_falling_back_to_v2():
    cfg = load("nvd")
    base = {"cve": {"id": "CVE-2026-0001", "lastModified": "2026-10-31T05:49:32.123",
                    "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Buffer overflow in foo"}], "metrics": {}}}
    v31 = {"cve": {**base["cve"], "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}],
                                               "cvssMetricV2": [{"baseSeverity": "MEDIUM"}]}}}
    v2 = {"cve": {**base["cve"], "metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH"}]}}}
    s = cfg.streams[0]
    row = normalise(v31, s, "nvd")
    assert (row["id"], row["type"], row["severity"], row["description"], row["timestamp"]) == (
        "CVE-2026-0001", "vulnerability", "critical", "Buffer overflow in foo", "2026-10-31T05:49:32Z")
    assert normalise(v2, s, "nvd")["severity"] == "high"
    assert normalise(base, s, "nvd")["severity"] == "info"  # not yet scored


def test_missing_event_id_falls_back_to_stable_hash():
    cfg = load("aws_cloudtrail", stream={"mapping": {"description": "eventName"}, "required_fields": []})
    s = cfg.streams[0]
    a = normalise({"eventName": "x", "n": 1}, s, "x")["id"]
    assert a == normalise({"n": 1, "eventName": "x"}, s, "x")["id"]
    assert a != normalise({"eventName": "x", "n": 2}, s, "x")["id"]


def test_real_okta_user_and_jira_shapes():
    okta = load("okta")
    row = normalise({"id": "00ub0oNGTSWTBKOLGLNR", "status": "ACTIVE", "lastLogin": "2026-10-29T15:04:05.000Z",
                     "profile": {"firstName": "Isaac", "lastName": "Brock", "email": "isaac.brock@example.com"}},
                    okta.stream("users"), "okta")
    assert (row["name"], row["email"], row["last_login"]) == ("Isaac Brock", "isaac.brock@example.com", "2026-10-29T15:04:05Z")
    jira = load("jira")
    u = normalise({"accountId": "5b10ac8d82e05b22cc7d4ef5", "displayName": "Mia Krystof", "emailAddress": "mia@example.com", "active": False},
                  jira.stream("users"), "jira")
    assert (u["id"], u["name"], u["status"]) == ("5b10ac8d82e05b22cc7d4ef5", "Mia Krystof", "inactive")
    issue = normalise({"key": "SOC-12", "fields": {"summary": "Phishing report", "priority": {"name": "Highest"},
                                                   "issuetype": {"name": "Bug"}, "updated": "2026-10-30T10:00:00.000+0530"}},
                      jira.stream("issues"), "jira")
    assert (issue["id"], issue["type"], issue["severity"], issue["timestamp"]) == ("SOC-12", "Bug", "critical", "2026-10-30T04:30:00Z")
