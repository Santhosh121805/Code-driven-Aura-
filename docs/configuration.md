# Configuration reference

How to describe a tool in YAML (or with the wizard).

[← Back to the docs index](README.md)

## Add an integration (config, not code)

Use the **Add integration** wizard (Basics → Auth → Request → Pagination → Mapping → Test → Save), or drop a YAML file in `configs/integrations/` (live within 5 s). One config can have several streams:

```yaml
name: okta
display_name: "Okta"
base_url: "https://${OKTA_DOMAIN}"                 # non-secret settings can come from .env too
auth: { type: api_key, header: Authorization, prefix: "SSWS ", api_key: "${okta_token}" }   # secret by NAME only
scopes: ["okta.users.read", "okta.logs.read"]
schedule_seconds: 900                              # FR-4: every 15 minutes
rate_limit: { reset_header: x-rate-limit-reset, remaining_header: x-rate-limit-remaining }
streams:
  - name: users
    entity: user                                   # user | device | event
    endpoint: /api/v1/users
    params: { limit: 200 }
    pagination: { type: link }
    mapping:
      id: id
      name: "join(' ', [profile.firstName || '', profile.lastName || ''])"   # combine + nested values
      email: profile.email
      status: status
      last_login: lastLogin                        # dates converted to ISO 8601 UTC
  - name: events
    entity: event
    endpoint: /api/v1/logs
    params: { since: "{{ last_sync }}" }           # B-1 incremental sync
    pagination: { type: link }
    mapping: { id: uuid, type: eventType, severity: severity, timestamp: published, description: displayMessage }
    transforms: { severity_map: { DEBUG: info, INFO: info, WARN: medium, ERROR: high } }
```

Other options: `requires_env` (skip a stream unless a variable is set), `fallback_for` (use a stream only when another returns 403/404), `required_fields`, `default_severity`, `custom_step` (a rare plugin hook). The full JSON Schema is at `GET /api/schema`.
