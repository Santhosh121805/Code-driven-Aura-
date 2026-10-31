"""Mock AWS CloudTrail (port 9001).

Auth: Bearer token (MOCK_CLOUDTRAIL_TOKEN) - a stand-in for SigV4 signing.
Pagination: NextToken. GET /events?StartTime=&NextToken= -> {"Records": [...], "NextToken": "..."} (NextToken omitted on the last page)
Records follow the CloudTrail record format: eventID, eventName, eventTime, userIdentity.arn, sourceIPAddress, awsRegion, ...
Also GET /kev: a public (no-auth) CISA KEV-style feed.
Demo controls: POST /__demo/bulk-export-next?multiplier=20 makes the next page return 20x the normal volume.
"""
from __future__ import annotations

import base64
import json
import random
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tests.fakes.common import (
    EXTERNAL_IPS, MALFORMED_KINDS, USERS, add_demo_controls, check_bearer, env, inject_malformed, private_ip, recent_time,
    sprinkle_malformed,
)

TOTAL_PAGES = 3
PAGE_SIZE = 4
ACCOUNT = "491085362710"
REGIONS = ["ap-south-1"] * 6 + ["ap-southeast-1", "us-east-1", "eu-west-1"]
KEV_FILE = Path(__file__).parent / "data" / "kev.json"
# (key, eventName, eventSource, weight). Severity is NOT in the data: the platform derives it from eventName via severity_map.
CATALOG = [
    ("get_object", "GetObject", "s3.amazonaws.com", 18),
    ("list_buckets", "ListBuckets", "s3.amazonaws.com", 10),
    ("describe", "DescribeInstances", "ec2.amazonaws.com", 12),
    ("assume_role", "AssumeRole", "sts.amazonaws.com", 10),
    ("login_ok", "ConsoleLogin", "signin.amazonaws.com", 12),
    ("login_fail", "ConsoleLogin", "signin.amazonaws.com", 12),
    ("denied", "ListBuckets", "s3.amazonaws.com", 6),
    ("open_sg", "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", 7),
    ("access_key", "CreateAccessKey", "iam.amazonaws.com", 5),
    ("public_bucket", "PutBucketPolicy", "s3.amazonaws.com", 5),
    ("stop_logging", "StopLogging", "cloudtrail.amazonaws.com", 2),
    ("delete_trail", "DeleteTrail", "cloudtrail.amazonaws.com", 1),
]

app = FastAPI(title="Mock AWS CloudTrail")
controls = add_demo_controls(app)
EXFIL_USER, EXFIL_IP = "svc-sales-integration", "45.155.205.233"


def _token() -> str:
    return env("MOCK_CLOUDTRAIL_TOKEN", "ct-demo-token-5e2b7d")


def _encode(page: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"page": page}).encode()).decode()


def _decode(token: str | None) -> int:
    try:
        return int(json.loads(base64.urlsafe_b64decode(token.encode()))["page"]) if token else 1
    except Exception:
        return 1


def record(since: str | None = None, kind: str | None = None, user: str | None = None, ip: str | None = None) -> dict:
    key, name, source, _ = next(c for c in CATALOG if c[0] == kind) if kind else random.choices(CATALOG, weights=[c[3] for c in CATALOG])[0]
    user = user or random.choice(USERS)
    console = source == "signin.amazonaws.com"
    rec = {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "principalId": "AIDA" + uuid.uuid4().hex[:16].upper(),
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}", "accountId": ACCOUNT, "userName": user},
        "eventTime": recent_time(since).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": random.choice(REGIONS),
        "sourceIPAddress": ip or (random.choice(EXTERNAL_IPS) if random.random() < 0.3 else private_ip()),
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" if console else "aws-cli/2.15.30 Python/3.11.8",
        "requestParameters": None,
        "responseElements": None,
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": key in ("get_object", "list_buckets", "describe", "denied"),
        "eventType": "AwsConsoleSignIn" if console else "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    if key == "login_ok":
        rec["responseElements"] = {"ConsoleLogin": "Success"}
    elif key == "login_fail":
        rec["responseElements"] = {"ConsoleLogin": "Failure"}
        rec["errorMessage"] = "Failed authentication"
    elif key == "denied":
        rec["errorCode"], rec["errorMessage"] = "AccessDenied", "User is not authorized to perform s3:ListAllMyBuckets"
    elif key == "get_object":
        rec["requestParameters"] = {"bucketName": random.choice(["finance-exports", "hr-payroll-docs", "app-logs-mumbai"]),
                                    "key": f"reports/{uuid.uuid4().hex[:8]}.csv"}
    elif key == "open_sg":
        rec["requestParameters"] = {"groupId": "sg-0a1b2c3d", "ipPermissions": {"fromPort": 22, "toPort": 22, "cidrIp": "0.0.0.0/0"}}
    elif key == "public_bucket":
        rec["requestParameters"] = {"bucketName": "finance-exports",
                                    "bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}
    elif key in ("stop_logging", "delete_trail"):
        rec["requestParameters"] = {"name": f"arn:aws:cloudtrail:ap-south-1:{ACCOUNT}:trail/org-trail"}
    elif key == "access_key":
        rec["requestParameters"] = {"userName": random.choice(USERS)}
    return rec


def malform(rec: dict, kind: str | None = None) -> dict:
    """A realistic broken record: missing eventID, garbage eventTime, or an object where the ARN string belongs."""
    rec = json.loads(json.dumps(rec))
    kind = kind or random.choice(MALFORMED_KINDS)
    if kind == "missing_id":
        rec.pop("eventID", None)
    elif kind == "bad_time":
        rec["eventTime"] = "not-a-timestamp"
    else:
        rec["userIdentity"]["arn"] = {"truncated": True}
    return rec


@app.get("/events")
def events(request: Request, StartTime: str | None = None, NextToken: str | None = None) -> dict:  # noqa: N803 (AWS casing)
    check_bearer(request, _token())
    page = _decode(NextToken)
    multiplier = controls.take_bulk()
    if multiplier:
        # Simulated stolen-token bulk export: one integration identity pulls every object it can reach.
        records = [record(StartTime, kind="get_object", user=EXFIL_USER, ip=EXFIL_IP) for _ in range(PAGE_SIZE * multiplier)]
    else:
        records = sprinkle_malformed([record(StartTime) for _ in range(PAGE_SIZE)], malform)
    body: dict = {"Records": inject_malformed(records, controls, malform, lambda: record(StartTime))}
    if page < TOTAL_PAGES:
        body["NextToken"] = _encode(page + 1)
    return body


@app.get("/kev")
def kev() -> JSONResponse:
    """Public feed, no auth: a saved copy of a CISA KEV-style catalogue."""
    return JSONResponse(json.loads(KEV_FILE.read_text(encoding="utf-8")))


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "mock_cloudtrail"}


if __name__ == "__main__":
    uvicorn.run(app, host=env("BIND_HOST", "127.0.0.1"), port=int(env("MOCK_CLOUDTRAIL_PORT", "9001")), log_level="warning")
