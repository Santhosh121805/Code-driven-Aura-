"""B-2: human-friendly validation errors; secrets only as ${NAME} references; streams consistent with their entity."""
import copy

import pytest

from integration_platform.config import ConfigError, parse_yaml, validate_action, validate_integration
from tests.conftest import ROOT

BASE = parse_yaml((ROOT / "configs/integrations/aws_cloudtrail.yaml").read_text())


def errors_for(mutate) -> list[str]:
    data = copy.deepcopy(BASE)
    mutate(data)
    with pytest.raises(ConfigError) as exc:
        validate_integration(data)
    return exc.value.errors


def stream(d):
    return d["streams"][0]


def test_seeded_configs_are_valid():
    names = []
    for path in (ROOT / "configs/integrations").glob("*.yaml"):
        names.append(validate_integration(parse_yaml(path.read_text())).name)
    assert {"aws_cloudtrail", "acme_firewall", "mock_okta", "github", "okta", "jira", "nvd"} <= set(names)
    for path in (ROOT / "configs/actions").glob("*.yaml"):
        validate_action(parse_yaml(path.read_text()))
    validate_integration(parse_yaml((ROOT / "configs/examples/cisa_kev.yaml").read_text()))


def test_auth_type_message():
    assert errors_for(lambda d: d["auth"].update(type="magic")) == [
        "auth.type must be one of: none, bearer, api_key, basic, oauth2_client_credentials"]


def test_pagination_type_message():
    assert errors_for(lambda d: stream(d).update(pagination={"type": "scroll"})) == [
        "streams.0.pagination.type must be one of: none, page, offset, cursor, link"]


@pytest.mark.parametrize("field,auth", [
    ("auth.token", {"type": "bearer", "token": "sk-live-1234567890"}),
    ("auth.api_key", {"type": "api_key", "api_key": "abc123"}),
    ("auth.password", {"type": "basic", "username": "bob", "password": "hunter2"}),
    ("auth.client_secret", {"type": "oauth2_client_credentials", "token_url": "/t", "client_id": "x", "client_secret": "s3cr3t"}),
])
def test_literal_secrets_rejected(field, auth):
    errs = errors_for(lambda d: d.update(auth=auth))
    assert len(errs) == 1 and errs[0].startswith(f"{field} must be an environment variable reference like ${{")


def test_sensitive_header_must_be_env_ref():
    errs = errors_for(lambda d: d.update(headers={"Authorization": "Bearer abc"}))
    assert "sensitive-looking header 'Authorization'" in errs[0]
    errs = errors_for(lambda d: stream(d).update(headers={"X-Api-Key": "abc"}))
    assert errs[0].startswith("streams.0.headers has a sensitive-looking header")


def test_missing_required_and_bad_name():
    errs = errors_for(lambda d: (d.pop("base_url"), d.update(name="Acme EDR!")))
    assert "base_url is required" in errs
    assert any(e.startswith("name must be") for e in errs)


def test_base_url_may_reference_env():
    data = copy.deepcopy(BASE)
    data["base_url"] = "https://${OKTA_DOMAIN}"
    assert validate_integration(data).base_url == "https://${OKTA_DOMAIN}"


def test_mapping_fields_must_belong_to_the_entity():
    errs = errors_for(lambda d: stream(d)["mapping"].update(hostname="x"))
    assert errs == ["streams.0 mapping field(s) hostname are not part of the event schema; use: "
                    "id, type, severity, timestamp, description, host, src_ip, dst_ip, user"]
    errs = errors_for(lambda d: stream(d).update(entity="user"))
    assert errs[0].startswith("streams.0 mapping field(s) type, timestamp, severity, description, user, src_ip are not part of the user schema")


def test_bad_jmespath_and_entity_messages():
    errs = errors_for(lambda d: stream(d)["mapping"].update(timestamp="detected_at["))
    assert any(e.startswith("streams.0.mapping.timestamp is not a valid JMESPath expression") for e in errs)
    assert errors_for(lambda d: stream(d).update(entity="host")) == ["streams.0.entity must be one of: user, device, event"]


def test_streams_required_and_unique():
    assert errors_for(lambda d: d.update(streams=[])) == ["streams needs at least one stream"]
    errs = errors_for(lambda d: d["streams"].append(copy.deepcopy(d["streams"][0])))
    assert errs == ["stream names must be unique (got events, events)"]
    errs = errors_for(lambda d: stream(d).update(fallback_for="nope"))
    assert errs == ["stream events: fallback_for 'nope' is not a stream of this integration"]


def test_enum_values_messages():
    assert errors_for(lambda d: stream(d)["transforms"].update(time_format="rfc")) == [
        "streams.0.transforms.time_format must be one of: iso8601, epoch_s, epoch_ms"]
    assert errors_for(lambda d: stream(d)["transforms"]["severity_map"].update({"5": "urgent"})) == [
        "streams.0.transforms.severity_map.5 must be one of: info, low, medium, high, critical"]


def test_unknown_field_and_yaml_syntax():
    assert errors_for(lambda d: d.update(colour="blue")) == ["colour is not a recognised field (check spelling)"]
    with pytest.raises(ConfigError, match="YAML syntax error"):
        parse_yaml("name: [oops")


def test_bad_action_template():
    data = parse_yaml((ROOT / "configs/actions/create_jira_ticket.yaml").read_text())
    data["body_template"] = "{{ description "
    with pytest.raises(ConfigError, match="body_template template syntax error"):
        validate_action(data)
