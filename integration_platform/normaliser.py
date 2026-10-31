"""Map raw tool records into the common schema: users, devices, events and repositories."""
from __future__ import annotations

import base64
import binascii
import contextvars
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import jmespath
from jmespath import functions

from integration_platform.config import ENTITY_FIELDS, SEVERITIES, STRUCTURED_FIELDS, TIME_FIELD, Stream, Transforms

_parent: contextvars.ContextVar[Any] = contextvars.ContextVar("parent", default=None)

_MD_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_HTML_TAG = re.compile(r"<[^>]+>")
_SKIP_LINE = re.compile(r"^\s*(#|!\[|\[!\[|<img|<p\b|<div|</|<!--|<h\d|<a\b[^>]*>\s*<img|[-*_=]{3,}\s*$|\||>)", re.I)


_URL = re.compile(r"https?://\S+")
_LIST_ITEM = re.compile(r"^\s*([-*+\u2192\u2022]|\d+[.)])\s+")
# Template text that says nothing about the project (generators and placeholders), matched case-insensitively.
_BOILERPLATE = ("there are several ways of editing", "this project was bootstrapped with", "this template provides a minimal setup",
                "getting started with create react app", "welcome to your", "todo: document your project", "automatically synced with your",
                "edit this readme", "replace this with")


def _blocks(text: str) -> list[tuple[str, bool]]:
    """README -> readable paragraphs as (clean text, is_list). Skips front matter, headings, badges, images, HTML, tables, code."""
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":  # YAML front matter (e.g. Hugging Face Spaces)
        close = next((i for i, l in enumerate(lines[1:], 1) if l.strip() == "---"), None)
        if close:
            lines = lines[close + 1:]
    blocks: list[tuple[str, bool]] = []
    current: list[str] = []
    is_list = False
    in_code = False

    def flush() -> None:
        nonlocal current, is_list
        if current:
            blocks.append((" ".join(" ".join(current).split()), is_list))
        current, is_list = [], False

    for line in lines:
        if line.lstrip().startswith(("```", "~~~")):
            in_code = not in_code
            flush()
            continue
        if in_code or not line.strip() or _SKIP_LINE.match(line):
            flush()
            continue
        clean = _HTML_TAG.sub("", _MD_LINK.sub(r"\1", line))
        clean = re.sub(r"[*_`]{1,3}", "", clean).strip()
        if not clean:
            continue
        if not current:
            is_list = bool(_LIST_ITEM.match(clean))
        current.append(clean)
    flush()
    return blocks


def _meaningful(block: str) -> bool:
    words = _URL.sub("", block).split()
    if len(words) < 4 or any(b in block.lower() for b in _BOILERPLATE):
        return False
    if block.count("\u00b7") >= 3 and all(len(part.split()) <= 3 for part in block.split("\u00b7")):
        return False  # a navigation row: "Overview · Architecture · Features · ..."
    if re.match(r"^[\w\s]{1,30}:\s*\S+$", block) and _URL.search(block):
        return False  # "URL: https://..."
    return True


def first_paragraph(text: str, max_len: int = 200) -> str | None:
    """First meaningful paragraph of a README: skips headings, badges, images, HTML, tables, code blocks, front matter,
    link-only lines, navigation rows and template boilerplate; prefers prose over bullet lists; strips Markdown
    links/emphasis and trims to max_len characters on a word boundary. None when nothing meaningful is left."""
    blocks = [(b, is_list) for b, is_list in _blocks(text) if _meaningful(b)]
    chosen = next((b for b, is_list in blocks if not is_list), None) or next((b for b, _ in blocks), None)
    if not chosen:
        return None
    if len(chosen) > max_len:
        chosen = chosen[:max_len].rsplit(" ", 1)[0].rstrip(".,;:") + "…"
    return chosen


class _Functions(functions.Functions):
    """Extra JMESPath functions for mappings (all pure, no I/O)."""

    @functions.signature()
    def _func_parent(self) -> Any:
        """The parent record of a for_each stream, e.g. parent().full_name."""
        return _parent.get()

    @functions.signature({"types": ["string", "null"]})
    def _func_base64_decode(self, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return base64.b64decode("".join(value.split()), validate=False).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return None

    @functions.signature({"types": ["string", "null"]}, {"types": ["number"]})
    def _func_first_paragraph(self, text: str | None, max_len: float) -> str | None:
        return first_paragraph(text, int(max_len)) if text else None

    @functions.signature({"types": ["string", "number", "null"]})
    def _func_days_until(self, value: Any) -> float | None:
        """Days from now until a timestamp (negative = in the past), e.g. days_until(expires) < `7`. null if unparseable."""
        when = parse_time(value)
        if when is None:
            return None
        delta = datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
        return round(delta.total_seconds() / 86400, 3)

    @functions.signature({"types": ["object", "null"]})
    def _func_percent_map(self, counts: dict | None) -> dict | None:
        """{"Python": 9000, "Shell": 1000} -> {"Python": {"bytes": 9000, "percent": 90.0}, ...}, largest first."""
        if counts is None:
            return None
        numbers = {k: v for k, v in counts.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
        total = sum(numbers.values()) or 1
        return {k: {"bytes": v, "percent": round(100 * v / total, 1)} for k, v in sorted(numbers.items(), key=lambda kv: -kv[1])}


_OPTIONS = jmespath.Options(custom_functions=_Functions())


def search(path: str, record: Any, parent: Any = None) -> Any:
    """jmespath.search with the platform's extra functions; parent() returns `parent`."""
    token = _parent.set(parent)
    try:
        return jmespath.search(path, record, options=_OPTIONS)
    finally:
        _parent.reset(token)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utcnow() -> str:
    return _iso(datetime.now(timezone.utc))


def _from_epoch(number: float) -> datetime:
    # Values above ~1e11 cannot be seconds (year 5138+), so treat them as milliseconds.
    if abs(number) > 1e11:
        number /= 1000
    return datetime.fromtimestamp(number, tz=timezone.utc)


def parse_time(value: Any, time_format: str = "iso8601") -> str | None:
    """Parse a timestamp in the configured format (falling back to auto-detection) into ISO 8601 UTC."""
    if value is None or value == "":
        return None
    try:
        if time_format == "epoch_s":
            return _iso(datetime.fromtimestamp(float(value), tz=timezone.utc))
        if time_format == "epoch_ms":
            return _iso(datetime.fromtimestamp(float(value) / 1000, tz=timezone.utc))
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    # iso8601, or the configured format failed: auto-detect.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _iso(_from_epoch(float(value)))
    text = str(value).strip()
    try:
        return _iso(_from_epoch(float(text)))
    except ValueError:
        pass
    try:
        return _iso(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%b %d %Y %H:%M:%S"):
        try:
            return _iso(datetime.strptime(text, fmt))
        except ValueError:
            continue
    return None


def map_severity(value: Any, transforms: Transforms) -> str:
    if value is None:
        return transforms.default_severity
    key = str(value).strip()
    if key in transforms.severity_map:
        return transforms.severity_map[key]
    lowered = {k.lower(): v for k, v in transforms.severity_map.items()}
    if key.lower() in lowered:
        return lowered[key.lower()]
    if key.lower() in SEVERITIES:
        return key.lower()
    return transforms.default_severity


def _text(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


class BadRecord(ValueError):
    """A record that cannot be normalised safely. It is quarantined with this reason; the run continues."""


def _kind(value: Any) -> str:
    return {dict: "an object", list: "a list", bool: "a boolean"}.get(type(value), type(value).__name__)


def normalise(record: Any, stream: Stream, source: str, fetched_at: str | None = None, parent: Any = None) -> dict[str, Any]:
    """Apply a stream's mapping + transforms to one raw record -> one common-schema row for stream.entity.
    `parent` is the parent record of a for_each stream (parent() in mappings).
    Raises BadRecord for data that must not be ingested (missing required field, wrong type, bad time)."""
    if not isinstance(record, dict):
        raise BadRecord(f"record is not a JSON object (got {_kind(record)})")
    entity, fields, time_field = stream.entity, ENTITY_FIELDS[stream.entity], TIME_FIELD[stream.entity]
    structured = STRUCTURED_FIELDS.get(entity, ())
    values: dict[str, Any] = {}
    for field in fields:
        path = stream.mapping.get(field)
        if not path:
            continue
        try:
            value = search(path, record, parent)
        except Exception:  # e.g. type error inside a JMESPath function
            value = None
        if field in structured:
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            elif value is not None:
                value = json.dumps([value] if field == "topics" else value, ensure_ascii=False)
        elif isinstance(value, (dict, list)) or (isinstance(value, bool) and field in ("id", time_field)):
            raise BadRecord(f"wrong type for {field}: '{path}' is {_kind(value)}, expected a single value")
        values[field] = value
    for field in stream.required:
        if field in stream.mapping and values.get(field) in (None, ""):
            raise BadRecord(f"missing required field {field} ('{stream.mapping[field]}' not found in record)")
    raw_time = values.get(time_field)
    when = parse_time(raw_time, stream.transforms.time_format) if raw_time not in (None, "") else None
    if raw_time not in (None, "") and when is None:
        raise BadRecord(f"unparseable time {raw_time!r} in '{stream.mapping[time_field]}' (expected {stream.transforms.time_format})")

    row: dict[str, Any] = {field: _text(values.get(field)) for field in fields}
    row["id"] = row["id"] or hashlib.sha1(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()[:16]
    row[time_field] = when
    if entity == "event":
        row["timestamp"] = when or utcnow()
        row["severity"] = map_severity(values.get("severity"), stream.transforms)
        row["type"] = row["type"] or stream.name
        row["description"] = row["description"] or "(no description)"
    row.update(source=source, stream=stream.name, entity=entity, fetched_at=fetched_at or utcnow(), raw=record)
    return row
