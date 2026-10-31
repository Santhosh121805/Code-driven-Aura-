"""AI mapping assistant: "AI suggests, code verifies, human approves".

1. Deterministic pre-processing: flatten, detect records_path, pagination hints, time format.
2. Mask secrets / personal data before anything leaves the machine.
3. Optional LLM suggestion (Anthropic SDK, or any OpenAI-compatible endpoint such as Sarvam), 10 s timeout (30 s for Sarvam).
4. Verify every suggested path against the sample with JMESPath.
5. Offline rule-based fallback (always available, also fills gaps the LLM left).
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx
import jmespath

from integration_platform import logmask
from integration_platform.config import ENTITY_FIELDS, SEVERITIES, TIME_FIELD
from integration_platform.normaliser import parse_time

log = logging.getLogger("ai_mapper")
LLM_TIMEOUT = 10.0
SARVAM_TIMEOUT = 30.0  # sarvam-105b reasons before it answers
THINK_BLOCK = re.compile(r"<think>.*?</think>", re.S | re.I)
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")
ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TOKENISH = re.compile(r"^[A-Za-z0-9_\-+/=.]{24,}$")
SECRET_KEY = re.compile(r"token|secret|password|passwd|api[_-]?key|authorization|cookie|session", re.I)


# ================================================================ 1. deterministic pre-processing
def jp_key(key: str) -> str:
    """Quote a key for JMESPath if it is not a plain identifier."""
    return key if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) else json.dumps(key)


def join_path(prefix: str, key: str) -> str:
    return f"{prefix}.{jp_key(key)}" if prefix else jp_key(key)


def find_record_arrays(obj: Any, path: str = "") -> list[tuple[str, int]]:
    """All arrays of objects in the document as (jmespath, length). '' means the document root."""
    found: list[tuple[str, int]] = []
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) for x in obj):
            found.append((path, len(obj)))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            found += find_record_arrays(value, join_path(path, key))
    return found


def detect_records_path(sample: Any) -> tuple[str | None, list[dict]]:
    """Largest array of objects (ties -> shallowest). Returns (records_path or None for root, records)."""
    arrays = find_record_arrays(sample)
    if not arrays:
        return None, [sample] if isinstance(sample, dict) else []
    path, _ = max(arrays, key=lambda a: (a[1], -a[0].count(".")))
    records = jmespath.search(path, sample) if path else sample
    return (path or None), records


def flatten(record: Any, prefix: str = "") -> dict[str, Any]:
    """Leaf paths of one record -> value. Lists of scalars are kept as a single leaf."""
    out: dict[str, Any] = {}
    if isinstance(record, dict):
        for key, value in record.items():
            path = join_path(prefix, key)
            if isinstance(value, dict):
                out.update(flatten(value, path))
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                continue  # nested arrays of objects can't map to one scalar field
            else:
                out[path] = value
    return out


def field_examples(records: list[dict], limit: int = 20) -> dict[str, list[Any]]:
    """path -> values seen across the first `limit` records (keeps first-seen order)."""
    examples: dict[str, list[Any]] = {}
    for record in records[:limit]:
        for path, value in flatten(record).items():
            examples.setdefault(path, []).append(value)
    return examples


def detect_time_format(values: list[Any]) -> str | None:
    for value in values:
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,14}(\.\d+)?", value)):
            number = float(value)
            if number > 1e11:
                return "epoch_ms"
            if number > 1e8:
                return "epoch_s"
        elif isinstance(value, str) and (ISO_TIME.match(value) or ISO_DATE.match(value)):
            return "iso8601"
    return None


def detect_pagination(sample: Any, link_header: bool = False) -> dict[str, Any]:
    """Look for pagination keys outside the record array (or a Link rel="next" header seen when fetching)."""
    hints: list[str] = []
    guess: dict[str, Any] = {"type": "none"}
    if link_header:
        return {"type": "link", "evidence": ['The response has a Link header with rel="next": follow next links.']}
    if isinstance(sample, list):
        hints.append("Response is a top-level list: usually limit/offset or a Link header (check the response headers).")
        return {"type": "offset", "evidence": hints, "limit_param": "limit", "offset_param": "offset"}
    leaves: dict[str, Any] = {}

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict,)):
                    walk(value, join_path(path, key))
                elif not isinstance(value, list):
                    leaves[join_path(path, key)] = value
    walk(sample)
    for path, value in leaves.items():
        name = path.split(".")[-1].lower()
        if "cursor" in name or name in ("next", "next_token", "nexttoken", "next_page_token", "continuation", "after"):
            hints.append(f"'{path}' looks like a cursor")
            guess = {"type": "cursor", "cursor_path": path, "cursor_param": "cursor"}
        elif name in ("total_pages", "totalpages", "page_count", "pages", "last_page") and guess["type"] != "cursor":
            hints.append(f"'{path}' looks like a total page count")
            guess = {"type": "page", "total_pages_path": path, "page_param": "page", "size_param": "page_size"}
        elif name in ("page", "current_page", "page_number") and guess["type"] == "none":
            hints.append(f"'{path}' looks like a page number")
            guess = {"type": "page", "page_param": "page", "size_param": "page_size"}
        elif name in ("offset", "skip", "start") and guess["type"] == "none":
            hints.append(f"'{path}' looks like an offset")
            guess = {"type": "offset", "limit_param": "limit", "offset_param": name}
    if not hints:
        hints.append("No pagination keys found.")
    guess["evidence"] = hints
    return guess


# ================================================================ 5. rule-based matcher
def _last(path: str) -> str:
    return path.split(".")[-1].strip('"').lower()


def _tokens(path: str) -> set[str]:
    """Name tokens, splitting on separators AND camelCase (userIdentity -> user, identity; sourceIPAddress -> source, ipaddress)."""
    return {t.lower() for t in re.split(r"[._\-\s\"]+|(?<=[a-z])(?=[A-Z])", path)} - {""}


def _is_ip(v: Any) -> bool:
    return isinstance(v, str) and bool(IPV4.match(v))


TIME_NAMES = {
    "timestamp": {"time", "timestamp", "date", "ts", "created", "detected", "occurred", "updated", "datetime", "at", "published", "added", "modified"},
    "last_login": {"lastlogin", "last_login", "lastlogon", "last_logon", "lastsignin", "last_sign_in", "last_signin", "lastlogintime"},
    "last_seen": {"lastseen", "last_seen", "lastcontact", "last_contact", "lastcheckin", "last_check_in", "last_checkin", "lastactive"},
}
OTHER_ENTITY = {
    "event": {"user", "device", "host", "src", "dst", "parent", "process", "rule", "tenant", "org", "actor", "account", "principal", "request"},
    "user": {"device", "host", "group", "org", "tenant", "manager", "creator", "transaction", "request"},
    "device": {"user", "owner", "group", "org", "tenant", "transaction", "request"},
}


def _parses_as_time(value: Any) -> bool:
    return not isinstance(value, bool) and detect_time_format([value]) is not None and parse_time(value) is not None


def _score(field: str, path: str, values: list[Any], entity: str = "event") -> float:
    """How likely `path` is the source for common-schema `field` of `entity` (0..1), from name + value patterns."""
    name, toks = _last(path), _tokens(path)
    sample = [v for v in values if v not in (None, "")]
    if not sample:
        return 0.0
    first = sample[0]
    all_str = all(isinstance(v, str) for v in sample)
    depth_penalty = 0.1 * path.count(".")
    is_email = all_str and all(EMAIL.match(v) for v in sample)

    if field == "id":
        other = toks & OTHER_ENTITY[entity]
        id_names = {"id", "uuid", "guid", "_id", "event_id", "eventid", "alert_id", "alertid", "event_uuid", "log_id",
                    "incident_id", "user_id", "userid", "accountid", "account_id", "device_id", "deviceid", "mac",
                    "mac_address", "macaddress", "serial", "serial_number", "serialnumber", "instance_id", "instanceid",
                    "agent_id", "cveid", "cve_id", "key"}
        if name in id_names:
            score = 0.95
        elif name.endswith(("_id", "uuid", "id")):
            score = 0.75
        else:
            return 0.0
        if entity == "user" and toks & {"user", "account"}:
            other -= {"user", "account"}
        unique = len(set(map(str, sample))) == len(sample)
        return max(0.0, score - depth_penalty - (0.5 if other else 0) - (0 if unique else 0.3))

    if field in TIME_NAMES:
        parses = _parses_as_time(first)
        if field == "timestamp":
            named = bool(toks & TIME_NAMES["timestamp"]) or name.endswith("_at")
            if named and parses:
                bonus = 0.05 if toks & {"created", "detected", "occurred", "timestamp", "ts", "time", "published", "added"} else 0
                return min(1.0, 0.85 + bonus - depth_penalty / 2)
            return 0.55 if parses else (0.3 if named else 0.0)
        if name in TIME_NAMES[field] and parses:
            return 0.95
        word = {"last_login": {"login", "logon", "signin", "sign"}, "last_seen": {"seen", "contact", "checkin", "active"}}[field]
        if "last" in toks and toks & word and parses:
            return 0.85
        return 0.45 if parses and "last" in toks else 0.0

    if field == "severity":
        if name in ("sev", "severity", "level", "priority", "risk", "risk_level", "criticality", "urgency", "severity_level", "impact", "baseseverity"):
            return 0.95 - depth_penalty / 2
        if toks & {"severity", "sev", "risk", "priority"}:
            return 0.7
        return 0.0

    if field == "description":
        if not all_str or not any(re.search(r"[A-Za-z]{3}", v) for v in sample):
            return 0.0
        table = {"title": 0.95, "threat_name": 0.95, "alert_name": 0.95, "summary": 0.9, "msg": 0.9, "message": 0.9,
                 "displaymessage": 0.9, "description": 0.85, "vulnerabilityname": 0.9, "event_name": 0.8, "eventname": 0.8,
                 "signature": 0.8, "rule_name": 0.8, "shortdescription": 0.75, "name": 0.65, "action": 0.6, "event": 0.6}
        if name in table:
            return table[name] - depth_penalty
        if toks & {"threat", "title", "message", "alert", "summary", "description"}:
            return 0.65 - depth_penalty
        if "name" in toks and not toks & {"user", "host", "first", "last", "display", "product", "vendor", "project"}:
            return 0.55 - depth_penalty
        return 0.0

    if field == "type":
        if not all_str or any(len(v) > 60 for v in sample):
            return 0.0
        table = {"type": 0.8, "eventtype": 0.9, "event_type": 0.9, "category": 0.75, "kind": 0.7, "action": 0.6, "eventname": 0.6}
        if name in table:
            return table[name] - depth_penalty - (0.3 if toks & {"transaction", "actor", "user", "client"} else 0)
        return 0.0

    if field in ("host", "hostname"):
        if any(_is_ip(v) for v in sample) or any(isinstance(v, str) and "@" in v for v in sample) or not all_str:
            return 0.0
        if name in ("hostname", "host", "host_name", "computer_name", "computername", "machine", "device_name", "devicename", "endpoint", "fqdn"):
            return 0.95
        if toks & {"host", "hostname", "device", "computer", "machine"} and name in ("name", "displayname", "display_name"):
            return 0.75
        return 0.0

    if field in ("src_ip", "dst_ip", "ip"):
        if not all(_is_ip(v) for v in sample):
            return 0.0
        src = toks & {"src", "source", "client", "remote", "origin", "caller", "attacker"}
        dst = toks & {"dst", "dest", "destination", "target", "server"}
        if field == "ip":
            return 0.95 if toks & {"ip", "ipaddress", "ipv4", "address"} else 0.75
        if field == "src_ip":
            return 0.95 if src else (0.0 if dst else 0.75)
        return 0.95 if dst else 0.0

    if field == "os":
        if not all_str:
            return 0.0
        if name in ("os", "os_name", "osname", "operating_system", "operatingsystem", "platform", "platform_name", "os_version", "osversion"):
            return 0.9 - (0.1 if "version" in name else 0)
        return 0.75 if toks & {"os", "platform", "operating"} else 0.0

    if field in ("user", "owner"):
        bonus = 0.15 if is_email else 0.0  # an email-valued field beats a sibling id/display name
        names = ("user", "username", "user_name", "email", "user_email", "upn", "account", "principal", "login", "actor",
                 "owner", "assigned_to", "assigned_user", "last_login_user", "primary_user")
        if name in names:
            return 0.95 if is_email or name.startswith(("user", "owner")) else 0.85
        if toks & {"user", "account", "principal", "actor", "owner", "assigned"}:
            if toks & {"agent"}:
                return 0.0  # userAgent is not a user
            return min(0.95, 0.8 + bonus)
        return 0.6 if is_email else 0.0

    if field == "email":
        if not is_email:
            return 0.0
        return 0.95 if toks & {"email", "mail"} else (0.8 if toks & {"login", "username", "upn"} else 0.7)

    if field == "name":
        if not all_str or is_email:
            return 0.0
        if name in ("name", "displayname", "display_name", "fullname", "full_name", "realname"):
            return 0.9 - depth_penalty / 2
        if name in ("login", "username", "user_name"):
            return 0.6
        return 0.0

    if field == "status":
        if name in ("status", "state", "account_status", "accountstatus", "active", "enabled", "role_name"):
            return 0.9 - depth_penalty / 2 - (0.4 if toks & {"outcome", "transaction"} else 0)
        return 0.0
    return 0.0


SEVERITY_WORDS = {
    "info": "info", "informational": "info", "information": "info", "notice": "info", "debug": "info", "none": "info", "ok": "info",
    "low": "low", "minor": "low", "lo": "low",
    "warn": "medium", "warning": "medium", "medium": "medium", "moderate": "medium", "med": "medium", "suspicious": "medium",
    "high": "high", "major": "high", "error": "high", "severe": "high", "hi": "high",
    "critical": "critical", "crit": "critical", "alert": "critical", "emergency": "critical", "fatal": "critical", "urgent": "critical",
    "p1": "critical", "p2": "high", "p3": "medium", "p4": "low", "p5": "info",
}
# Known value families: if any member is observed, map the whole family (random samples rarely show every level).
SEVERITY_FAMILIES = [["debug", "info", "warn", "error"], ["info", "warn", "alert"], ["low", "medium", "high", "critical"],
                     ["p1", "p2", "p3", "p4", "p5"], ["informational", "low", "medium", "high", "critical"]]
# Scale-aware overrides: e.g. in a DEBUG/INFO/WARN/ERROR scale (Okta System Log) ERROR is the top level -> critical.
FAMILY_OVERRIDES = {"debug": {"error": "critical"}}


def suggest_severity_map(values: list[Any]) -> dict[str, str]:
    observed = [v for v in values if v is not None and not isinstance(v, bool)]
    if not observed:
        return {}
    numeric = [v for v in observed if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit())]
    if numeric and len(numeric) == len(observed):
        nums = sorted({int(float(v)) for v in numeric})
        lo, hi = min(nums), max(nums)
        if lo >= 1 and hi <= 4:
            return {"1": "low", "2": "medium", "3": "high", "4": "critical"}
        if lo >= 0 and hi <= 5:
            return {"0": "info", "1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
        if hi <= 10:
            return {str(n): ("info" if n <= 1 else "low" if n <= 3 else "medium" if n <= 6 else "high" if n <= 8 else "critical") for n in range(lo, 11)}
        return {str(n): ("low" if n < 40 else "medium" if n < 70 else "high" if n < 90 else "critical") for n in nums}
    words = [str(v).strip() for v in observed]
    upper = all(w.isupper() for w in words)
    lowered = {w.lower() for w in words}
    keys: list[str] = list(dict.fromkeys(words))
    # The family sharing the most values with the sample (ties -> first listed).
    family = max(SEVERITY_FAMILIES, key=lambda f: len(lowered & set(f)))
    family = family if lowered & set(family) else []
    keys += [m.upper() if upper else m for m in family]
    overrides = FAMILY_OVERRIDES.get(family[0], {}) if family else {}
    out: dict[str, str] = {}
    for key in dict.fromkeys(keys):
        mapped = overrides.get(key.lower()) or SEVERITY_WORDS.get(key.lower())
        if mapped:
            out[key] = mapped
    return out


def rule_based_mapping(examples: dict[str, list[Any]], entity: str = "event") -> dict[str, tuple[str, float]]:
    """Greedy best-match assignment: each common field gets at most one path, each path one field."""
    fields = ENTITY_FIELDS[entity]
    candidates = [(score, field, path) for field in fields for path, values in examples.items()
                  if (score := _score(field, path, values, entity)) >= 0.4]
    candidates.sort(key=lambda c: (-c[0], fields.index(c[1]), c[2].count(".")))
    chosen: dict[str, tuple[str, float]] = {}
    used: set[str] = set()
    for score, field, path in candidates:
        if field in chosen or path in used:
            continue
        chosen[field] = (path, round(min(score, 1.0), 2))
        used.add(path)
    return chosen


def name_from_parts(examples: dict[str, list[Any]]) -> str | None:
    """firstName + lastName siblings (e.g. Okta profile.firstName / profile.lastName) -> one JMESPath join."""
    for path in examples:
        if _last(path) in ("firstname", "first_name", "givenname", "given_name"):
            prefix = path.rsplit(".", 1)[0] + "." if "." in path else ""
            last = next((p for p in examples if p.startswith(prefix) and _last(p) in ("lastname", "last_name", "familyname", "family_name", "surname")), None)
            if last:
                return f"join(' ', [{path} || '', {last} || ''])"
    return None


# ================================================================ 2. masking
def mask(value: Any, key: str = "") -> Any:
    """Replace secret-like and personal values before sending a sample to an LLM."""
    if isinstance(value, dict):
        return {k: mask(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, key) for v in value]
    if isinstance(value, str):
        if SECRET_KEY.search(key):
            return "<redacted-secret>"
        if EMAIL.match(value):
            return "user@example.com"
        if TOKENISH.match(value) and not ISO_TIME.match(value) and len(set(value)) > 10:
            return "<redacted-token>"
    return value


# ================================================================ 3. LLM call (provider-agnostic)
PROMPT = """You map security-tool API responses onto one entity of a common schema: {entity}.
Fields for {entity}: {fields}.
Severity values (events only) must be one of: info, low, medium, high, critical.

Pre-processing already found:
- records_path (JMESPath to the record list, null = document root): {records_path}
- leaf paths inside ONE record, with example values: {paths}

Sample response (secrets/emails masked):
{sample}

Reply with ONLY one JSON object, no prose, exactly this shape:
{{"records_path": "<jmespath or null>",
  "mapping": {{"<common field>": "<jmespath relative to one record>"}},
  "severity_map": {{"<raw value as string>": "<info|low|medium|high|critical>"}},
  "time_format": "<iso8601|epoch_s|epoch_ms>",
  "confidence": {{"<common field>": <0..1>}},
  "notes": "<one short sentence>"}}
Only use paths that exist in the sample. Omit fields you cannot map."""


def llm_provider() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("LLM_BASE_URL") and os.environ.get("LLM_MODEL"):
        return "openai_compatible"
    return None


def _extract_json(text: str) -> dict[str, Any]:
    """The JSON object in a model reply, ignoring reasoning text, <think> blocks and code fences around it."""
    text = THINK_BLOCK.sub("", text or "")
    decoder = json.JSONDecoder()
    found: list[dict[str, Any]] = []
    i = text.find("{")
    while i >= 0:
        try:
            obj, end = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            i = text.find("{", i + 1)
            continue
        if isinstance(obj, dict):
            found.append(obj)
        i = text.find("{", end)
    if not found:
        raise ValueError("LLM reply contained no JSON object")
    # Prefer the answer over braces quoted in the reasoning ("a record looks like {...}").
    return next((obj for obj in reversed(found) if "mapping" in obj), found[-1])


def _call_anthropic(prompt: str) -> tuple[dict[str, Any], str]:
    import anthropic  # optional dependency: only needed when ANTHROPIC_API_KEY is set

    model = os.environ.get("ANTHROPIC_MODEL") or "claude-opus-5-5"
    client = anthropic.Anthropic(timeout=LLM_TIMEOUT, max_retries=0)
    # Server-side refusal fallback ("default" routing) so a false-positive decline still gets an answer.
    response = client.beta.messages.create(
        model=model,
        max_tokens=2000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={"effort": "low"},  # small extraction task; keeps us inside the 10 s budget
        messages=[{"role": "user", "content": prompt}],
    )
    if response.stop_reason == "refusal":
        raise ValueError("model declined the request")
    text = "".join(block.text for block in response.content if block.type == "text")
    return _extract_json(text), f"anthropic/{response.model}"


def _call_openai_compatible(prompt: str) -> tuple[dict[str, Any], str]:
    base = os.environ["LLM_BASE_URL"].rstrip("/")
    model = os.environ["LLM_MODEL"]
    sarvam = "sarvam.ai" in base
    key = os.environ.get("LLM_API_KEY")
    if key:
        logmask.remember(key)
    # Bearer is the OpenAI convention; Sarvam's native header is api-subscription-key, tried if Bearer is rejected.
    header_options = [{"Authorization": f"Bearer {key}"}, {"api-subscription-key": key}] if key else [{}]
    body = {"model": model, "temperature": 0,
            "messages": [{"role": "system", "content": "Reply with strict JSON only."}, {"role": "user", "content": prompt}]}
    if sarvam:
        # Thinking mode spends Sarvam's whole default 2048-token budget on reasoning and returns no content;
        # with reasoning off it answers this extraction task in ~2 s.
        body.update(reasoning_effort=None, max_tokens=4096)
    for headers in header_options:
        resp = httpx.post(f"{base}/chat/completions", headers=headers, timeout=SARVAM_TIMEOUT if sarvam else LLM_TIMEOUT, json=body)
        if resp.status_code not in (401, 403):
            break
    resp.raise_for_status()
    # Reasoning models may also send reasoning_content: only the answer in content is used.
    content = resp.json()["choices"][0]["message"].get("content") or ""
    return _extract_json(content), "Sarvam" if sarvam else f"openai-compatible/{model}"


def call_llm(sample: Any, records_path: str | None, examples: dict[str, list[Any]], entity: str = "event") -> tuple[dict[str, Any], str]:
    masked = mask(sample)  # mask() builds new containers, so truncating below never touches `sample`
    # Keep the prompt small: at most 3 records.
    if isinstance(masked, list):
        masked = masked[:3]
    elif records_path:
        masked = _truncate_at(masked, records_path, 3)
    paths = {p: mask(v[0], p) for p, v in examples.items()}
    prompt = PROMPT.format(entity=entity, fields=", ".join(ENTITY_FIELDS[entity]), records_path=json.dumps(records_path),
                           paths=json.dumps(paths, default=str),
                           sample=json.dumps(masked, default=str)[:6000])
    if llm_provider() == "anthropic":
        return _call_anthropic(prompt)
    return _call_openai_compatible(prompt)


def _truncate_at(doc: Any, path: str, n: int) -> Any:
    """Truncate the list at a simple dotted path (as produced by detect_records_path) to n items."""
    keys = [k.strip('"') for k in re.findall(r'"[^"]*"|[^.]+', path)]
    node = doc
    for key in keys[:-1]:
        node = node.get(key) if isinstance(node, dict) else None
    if isinstance(node, dict) and isinstance(node.get(keys[-1]), list):
        node[keys[-1]] = node[keys[-1]][:n]
    return doc


# ================================================================ 4. verification
def verify_suggestion(suggestion: dict[str, Any], sample: Any, detected_records_path: str | None, entity: str = "event") -> dict[str, Any]:
    """Check every LLM-suggested path against the real sample. Bad paths are dropped and marked 'needs manual'."""
    notes: list[str] = []
    records_path = suggestion.get("records_path") or None
    records: Any = None
    if records_path:
        try:
            records = jmespath.search(records_path, sample)
        except Exception:
            records = None
    else:
        records = sample if isinstance(sample, list) else None
    if not (isinstance(records, list) and records and isinstance(records[0], dict)):
        if records_path != detected_records_path:
            notes.append(f"Suggested records_path {records_path!r} did not match the sample; using detected {detected_records_path!r}.")
        records_path = detected_records_path
        records = jmespath.search(records_path, sample) if records_path else sample
    records = records if isinstance(records, list) else [records]
    records = [r for r in records if isinstance(r, dict)][:20]

    fields: dict[str, dict[str, Any]] = {}
    raw_mapping = suggestion.get("mapping") or {}
    raw_conf = suggestion.get("confidence") or {}
    severity_map = {str(k): v for k, v in (suggestion.get("severity_map") or {}).items() if v in SEVERITIES}
    for field, path in raw_mapping.items():
        if field not in ENTITY_FIELDS[entity]:
            notes.append(f"Ignored unknown field '{field}'.")
            continue
        if path in (None, ""):  # some models answer "" instead of omitting the field: not mapped, rules fill it
            continue
        conf = float(raw_conf.get(field, 0.7)) if isinstance(raw_conf.get(field, 0.7), (int, float)) else 0.7
        entry = {"field": field, "path": path, "confidence": round(max(0.0, min(conf, 1.0)), 2), "source": "ai", "status": "ok", "note": ""}
        try:
            values = [jmespath.search(str(path), r) for r in records]
        except Exception:
            values = []
            entry.update(status="needs_manual", path="", confidence=0.0, note=f"'{path}' is not valid JMESPath")
        present = [v for v in values if v not in (None, "")]
        if entry["status"] == "ok" and not present:
            entry.update(status="needs_manual", path="", confidence=0.0, note=f"Path '{path}' does not exist in the sample")
        elif field == "severity" and not any(str(v).lower() in SEVERITIES or str(v) in severity_map for v in present):
            # The path exists but holds free text (e.g. KEV requiredAction): no value is a severity or a severity_map key.
            entry.update(status="needs_manual", path="", confidence=0.0, note=f"Values like {str(present[0])[:60]!r} are not severities")
        elif entry["status"] == "ok":
            entry["example"] = present[0]
            mismatch = (
                (field == TIME_FIELD[entity] and parse_time(present[0]) is None)
                or (field in ("src_ip", "dst_ip", "ip") and not _is_ip(present[0]))
                or (field == "email" and not (isinstance(present[0], str) and EMAIL.match(present[0])))
                or isinstance(present[0], (dict, list))
            )
            if mismatch:
                entry["confidence"] = round(entry["confidence"] * 0.4, 2)
                entry["status"] = "low_confidence"
                entry["note"] = f"Value {present[0]!r} doesn't look like a {field}"
        fields[field] = entry

    time_format = suggestion.get("time_format") if suggestion.get("time_format") in ("iso8601", "epoch_s", "epoch_ms") else None
    if suggestion.get("notes"):
        notes.append(str(suggestion["notes"]))
    return {"records_path": records_path, "records": records, "fields": fields, "severity_map": severity_map,
            "time_format": time_format, "notes": notes}


# ================================================================ entry point
def suggest_mapping(sample: Any, entity: str = "event", use_llm: bool = True, link_header: bool = False) -> dict[str, Any]:
    """Suggest records_path + mapping (+ severity map / time format) from one sample response, for one entity."""
    if isinstance(sample, str):
        try:
            sample = json.loads(sample)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Sample is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})")
    if not isinstance(sample, (dict, list)):
        raise ValueError("Sample must be a JSON object or array (paste one full API response)")
    fields_order, time_field = ENTITY_FIELDS[entity], TIME_FIELD[entity]

    detected_path, records = detect_records_path(sample)
    records = [r for r in records if isinstance(r, dict)]
    if not records:
        raise ValueError("Could not find any records (objects) in the sample")
    examples = field_examples(records)
    pagination = detect_pagination(sample, link_header)
    rules = rule_based_mapping(examples, entity)

    engine, fallback_reason = "Rule-based fallback", None
    provider = llm_provider() if use_llm else None
    verified: dict[str, Any] | None = None
    if provider is None:
        fallback_reason = "No LLM configured (set ANTHROPIC_API_KEY or LLM_BASE_URL/LLM_MODEL)" if use_llm else "LLM disabled for this request"
    else:
        try:
            suggestion, model_label = call_llm(sample, detected_path, examples, entity)
            verified = verify_suggestion(suggestion, sample, detected_path, entity)
            engine = f"AI ({model_label})"
        except Exception as exc:  # timeout, no internet, bad JSON, missing SDK... -> rules
            log.warning("LLM mapping failed, using rules: %s", logmask.mask_text(str(exc)))
            fallback_reason = logmask.mask_text(f"LLM unavailable ({type(exc).__name__}: {str(exc)[:120]})")

    records_path = verified["records_path"] if verified else detected_path
    fields: dict[str, dict[str, Any]] = dict(verified["fields"]) if verified else {}
    notes: list[str] = list((verified or {}).get("notes", []))
    if verified and verified["records_path"] != detected_path:
        records = verified["records"]
        examples = field_examples(records)
        rules = rule_based_mapping(examples, entity)
    # Rules fill every field the AI did not (or could not) map.
    for field, (path, conf) in rules.items():
        if field not in fields or fields[field]["status"] == "needs_manual":
            if path in {f["path"] for f in fields.values()}:
                continue
            fields[field] = {"field": field, "path": path, "confidence": conf, "source": "rules", "status": "ok",
                             "note": "", "example": examples[path][0]}
    if entity == "user" and (fields.get("name") or {}).get("confidence", 0) < 0.8:
        if expr := name_from_parts(examples):
            example = jmespath.search(expr, records[0])
            fields["name"] = {"field": "name", "path": expr, "confidence": 0.85, "source": "rules", "status": "ok",
                              "note": "Combined first + last name", "example": example}
    default_severity = None
    if entity == "event":
        ids = examples.get((fields.get("id") or {}).get("path") or "", [])
        if ids and all(isinstance(v, str) and CVE_ID.match(v) for v in ids):
            if (fields.get("type") or {}).get("status") != "ok":
                fields["type"] = {"field": "type", "path": "'vulnerability'", "confidence": 0.8, "source": "rules", "status": "ok",
                                  "note": "Records are CVEs: constant type", "example": "vulnerability"}
            if (fields.get("severity") or {}).get("status") != "ok":
                default_severity = "high"
                notes.append("No severity field in this feed: defaulting to high (known/actively exploited vulnerabilities). Edit if needed.")
    for field in fields_order:
        fields.setdefault(field, {"field": field, "path": "", "confidence": 0.0, "source": "rules", "status": "needs_manual",
                                  "note": "No matching field found", "example": None})

    severity_map: dict[str, str] = {}
    if entity == "event":
        sev_path = fields["severity"]["path"]
        # An AI severity_map is only trusted if verification did not reject the AI's own severity path.
        ai_sev_rejected = ((verified or {}).get("fields", {}).get("severity") or {}).get("status") == "needs_manual"
        ai_map = None if ai_sev_rejected else (verified or {}).get("severity_map")
        severity_map = ai_map or suggest_severity_map(examples.get(sev_path, []) if sev_path else [])
    time_path = fields[time_field]["path"]
    time_format = (verified or {}).get("time_format") or detect_time_format(examples.get(time_path, [])) or "iso8601"

    ordered = [fields[f] for f in fields_order]
    return {
        "engine": engine,
        "fallback_reason": fallback_reason,
        "entity": entity,
        "records_path": records_path,
        "record_count": len(records),
        "fields": ordered,
        "mapping": {f["field"]: f["path"] for f in ordered if f["path"]},
        "severity_map": severity_map,
        "default_severity": default_severity,
        "time_format": time_format,
        "pagination_hint": pagination,
        "available_paths": [{"path": p, "example": v[0]} for p, v in examples.items()],
        "notes": notes,
    }
