# Integration catalog and gap analysis

The 35 researched tools, what the engine supports today and which capabilities are still missing.

[← Back to the docs index](README.md)

## Integration catalog and gap analysis

The 35 tools on the customer list are researched in `catalog/` (one YAML per tool: category, API style, auth, paging, main endpoint, doc link, how far each fact was verified, and a template when one is safe to offer). Templates are **not** active integrations: an admin opens one from the **Catalog** page with **Use template**, fills in the `.env` names and tests it.

Anything not confirmed in public vendor docs is marked *unverified* or *needs verification*; no template rests on a guessed endpoint.

| Status | Tools |
|---|---|
| **Connected** (0) | - |
| **Template ready** (5) | Fortinet FortiGate, Lacework FortiCNAPP, Netskope DLP, Sophos Intercept X, Trend Micro Vision One |
| **Needs verification** (10) | Cisco Secure Firewall, Forcepoint DLP, Juniper SRX, LogRhythm, ManageEngine Log360, OpenText ArcSight, Prisma Cloud, SonicWall, Trellix EDR, WatchGuard Firebox |
| **Needs capability** (16) | AWS Security Hub / GuardDuty, Check Point, CrowdStrike Cloud Security, Digital Guardian, Elastic Security, Google Security Command Center, Kaspersky EDR, Orca Security, Palo Alto Cortex XSIAM, Safetica, Sophos Firewall, Symantec DLP, Symantec Endpoint Security, Trellix DLP, Wiz, Zscaler DLP |
| **No public API** (4) | Binary Search, Gurucul, Seceon, Seqrite XDR |

### What the engine has today

| Area | Supported |
|---|---|
| Auth | None, API key header (with prefix), Bearer, Basic, OAuth2 client credentials, **session login (new)** |
| Paging | None, page number, limit/offset, cursor (query parameter), next link (Link header or body path) |
| Request | GET / POST with a static JSON body, query params with `{{ last_sync }}` / date windows, `${NAME}` in URLs and headers |
| Mapping | JMESPath (nested paths, joins, constants), severity maps, ISO / epoch time formats, quarantine of bad records |
| Reliability | 1 s / 2 s / 4 s retries, no retry on 401/403, Retry-After / reset headers, pacing, alert after 3 failures |
| Safety | Secrets by name, encrypted vault, log masking, token-abuse guard, roles and audit |

### Capabilities the list needs

| Capability | Status | Needed by | Tools | No other capability missing |
|---|---|---|---|---|
| Request-body pagination (incl. GraphQL cursors) | Missing | 7 | Check Point, Elastic Security, Orca Security, Palo Alto Cortex XSIAM, Symantec DLP, Symantec Endpoint Security, Wiz | Check Point, Elastic Security, Orca Security, Palo Alto Cortex XSIAM, Symantec DLP, Symantec Endpoint Security, Wiz |
| Two-step ID lookup | Missing | 2 | CrowdStrike Cloud Security, Trellix DLP | CrowdStrike Cloud Security, Trellix DLP |
| Syslog / webhook receiver | Missing | 2 | Safetica, Zscaler DLP | Safetica, Zscaler DLP |
| AWS SigV4 request signing | Missing | 1 | AWS Security Hub / GuardDuty | AWS Security Hub / GuardDuty |
| Service-account JWT (Google OAuth2) | Missing | 1 | Google Security Command Center | Google Security Command Center |
| XML request / response | Missing | 1 | Sophos Firewall | Sophos Firewall |
| RPC-style session API | Missing | 1 | Kaspersky EDR | Kaspersky EDR |
| Export acknowledge (bookmark) | Missing | 1 | Digital Guardian | Digital Guardian |
| Session-login token auth | **Implemented** | 8 | Check Point, Cisco Secure Firewall, Forcepoint DLP, Kaspersky EDR, Lacework FortiCNAPP, OpenText ArcSight, Prisma Cloud, SonicWall | n/a |

Session-login was the most-needed capability (8 tools) and is now built (`auth: { type: session_login }`). With it, Lacework FortiCNAPP is template-ready; Prisma Cloud, Forcepoint DLP, Cisco Secure Firewall, OpenText ArcSight and SonicWall now only need their events endpoint confirmed; Check Point still needs request-body pagination and Kaspersky an RPC-style API. The next most valuable capability is **request-body pagination** (7 tools).

**Live proof (Mock):** the Fortinet FortiGate and Lacework FortiCNAPP templates run end to end in `tests/test_catalog.py` against `tests/fakes/mock_fortigate.py` and `tests/fakes/mock_lacework.py`, mocks that follow the vendors' documented request and response shapes.

<details><summary>All 35 tools</summary>

| Tool | Category | API | Auth | Paging | Endpoint | Status | Verified | Docs |
|---|---|---|---|---|---|---|---|---|
| Binary Search | SIEM | none public | unverified | unverified | `unverified` | No public API | unverified | - |
| Elastic Security | SIEM | REST pull (POST search with Elasticsearch query DSL) | API key (Authorization: ApiKey) | In the request body (from/size or search_after) | `POST /api/detection_engine/signals/search` | Needs capability: Request-body pagination (incl. GraphQL cursors) | partly verified | [link](https://www.elastic.co/docs/reference/elastic-cli/cli/stack/kb/security-detections-api) |
| Gurucul | SIEM | none public | unverified | unverified | `unverified` | No public API | unverified | [link](https://gurucul.com) |
| LogRhythm | SIEM | REST pull | Bearer token (third-party application token) | unverified | `unverified (alarms endpoint)` | Needs verification | partly verified | [link](https://developers.exabeam.com/logrhythm-siem/docs/authentication-and-bearer-token-usage) |
| ManageEngine Log360 | SIEM | REST pull | Bearer auth token (scoped, from API Settings) | unverified | `POST /RestAPI/v1/alerts (v1: no new tokens; supported until Sep 2026)` | Needs verification | partly verified | [link](https://www.manageengine.com/log-management/help/api-settings/synchronous-alert.html) |
| OpenText ArcSight | SIEM | REST pull (ESM service layer) | Session login (LoginService/login returns authToken) | unverified | `unverified (event query service)` | Needs verification | partly verified | [link](https://microfocus.com/documentation/arcsight/arcsight-esm-7.8/pdfdoc/ESM_ServiceLayer_DevGuide/ESM_ServiceLayer_DevGuide.pdf) |
| Palo Alto Cortex XSIAM | SIEM | REST pull | API key + x-xdr-auth-id headers | In the request body (request_data.search_from / search_to) | `POST /public_api/v1/alerts/get_alerts` | Needs capability: Request-body pagination (incl. GraphQL cursors) | verified | [link](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-REST-API/Get-all-Alerts) |
| Seceon | SIEM | none public | unverified | unverified | `unverified` | No public API | unverified | [link](https://seceon.atlassian.net/wiki/x/p4JKsQ) |
| Kaspersky EDR | EDR | RPC-style Open API (KLOAPI, Security Center) | Session (Basic / KSC token / web token) | unverified | `unverified (EDR-specific endpoints)` | Needs capability: RPC-style session API | partly verified | [link](https://support.kaspersky.com/help/KSC/15.1/KSCAPI/index.html) |
| Seqrite XDR | EDR | none public | unverified | unverified | `unverified` | No public API | unverified | [link](https://docs.seqrite.com) |
| Sophos Intercept X | EDR | REST pull (Sophos Central) | OAuth2 client credentials (id.sophos.com) + X-Tenant-ID header | unverified (single page in the template) | `GET /common/v1/alerts (regional host from whoami)` | Template ready | partly verified | [link](https://developer.sophos.com) |
| Symantec Endpoint Security | EDR | REST pull (ICDM event search) | OAuth2 client credentials | In the request body (cursor) | `unverified (event search request shape)` | Needs capability: Request-body pagination (incl. GraphQL cursors) | partly verified | [link](https://apidocs.securitycloud.symantec.com) |
| Trellix EDR | EDR | REST pull | OAuth2 client credentials (Trellix IAM, EDR scopes) | unverified | `GET /ft/api/v2/ft/threats (from an older third-party guide)` | Needs verification | partly verified | [link](https://docs.trellix.com/docs/trellix-edr-apis) |
| Trend Micro Vision One | EDR | REST pull | Bearer API key | Next link in the body (nextLink) | `GET /v3.0/workbench/alerts` | Template ready | partly verified | [link](https://automation.trendmicro.com) |
| Digital Guardian | DLP | REST pull (ARC export) | OAuth2 client credentials | Export bookmark advanced by an acknowledge call | `GET /rest/1.0/export/{export profile GUID}` | Needs capability: Export acknowledge (bookmark) | partly verified | [link](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/digitalguardian-edr) |
| Forcepoint DLP | DLP | REST pull | Session login (refresh-token call returns an access token) | unverified | `unverified (incidents call shape)` | Needs verification | verified | [link](https://help.forcepoint.com/dlp/10.4.0/restapi/A0AEF442-C3FC-48C2-8A21-BD82922CD645.html) |
| Netskope DLP | DLP | REST pull (data export iterator) | API token header (Netskope-Api-Token) | Server-side iterator (index + operation=next) | `GET /api/v2/events/dataexport/alerts/dlp` | Template ready | partly verified | [link](https://docs.netskope.com/en/rest-api-v2-overview/) |
| Safetica | DLP | Push (webhook / syslog to a SIEM) | n/a | n/a | `n/a (push)` | Needs capability: Syslog / webhook receiver | verified | [link](https://support.safetica.com/en/knowledge-base/send-alerts-to-siem) |
| Symantec DLP | DLP | REST pull (Enforce Incident API) | Basic (15.x) / forms login (16.x) | In the request body | `POST incidents query (Enforce REST)` | Needs capability: Request-body pagination (incl. GraphQL cursors) | partly verified | [link](https://knowledge.broadcom.com/external/article/215336/incident-reporting-and-update-restful-ap.html) |
| Trellix DLP | DLP | REST pull (ePO on-prem) | ePO credentials | Incident IDs since a time (max 1000), then details per ID | `Incident ID list + incident details` | Needs capability: Two-step ID lookup | verified | [link](https://docs.trellix.com/data-and-email/docs/rest-api-call-to-retrieve-incident-ids) |
| Zscaler DLP | DLP | Push (Nanolog Streaming Service) / ZIA API | Session with obfuscated API key + timestamp | unverified | `unverified (DLP events via API)` | Needs capability: Syslog / webhook receiver | unverified | [link](https://pyzscaler.readthedocs.io/en/latest/zs/zia/session.html) |
| Check Point | Firewall | REST pull (Management API) | Session login (/web_api/login returns sid, sent as X-chkp-sid) | In the request body (show-logs query id) | `POST /web_api/show-logs` | Needs capability: Request-body pagination (incl. GraphQL cursors) | partly verified | [link](https://community.checkpoint.com/t5/API-CLI-Discussion/API-Testing/m-p/160040) |
| Cisco Secure Firewall | Firewall | REST pull (FMC) | Session login (generatetoken: Basic in, token in a response header) | unverified | `unverified (events via REST)` | Needs verification | verified | [link](https://ciscolearning.github.io/cisco-learning-codelabs/posts/fmc-rest-token-authentication) |
| Fortinet FortiGate | Firewall | REST pull | API token (Authorization: Bearer) | Offset (start / rows, total_lines) | `GET /api/v2/log/memory/event/system` | Template ready | partly verified | [link](https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/940602) |
| Juniper SRX | Firewall | REST pull (Junos REST API, RPC over HTTP) | Basic | unverified | `unverified (log RPC)` | Needs verification | verified | [link](https://www.juniper.net/documentation/us/en/software/junos/rest-api/topics/concept/rest-api-overview.html) |
| SonicWall | Firewall | REST pull (SonicOS API) | Session login (Digest / CHAP / Basic on /api/sonicos/auth) | unverified | `unverified (log endpoint)` | Needs verification | verified | [link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-api/Content/SonicOS_API_Guide/API_Authentication/authentication-methods.htm) |
| Sophos Firewall | Firewall | XML API | Credentials inside each XML request | n/a | `POST /webconsole/APIController (reqxml)` | Needs capability: XML request / response | partly verified | [link](https://www.avanet.com/en/kb/sophos-firewall-api-zugriff-absichern/) |
| WatchGuard Firebox | Firewall | REST pull (WatchGuard Cloud) | OAuth2 client credentials + WatchGuard-API-Key header | unverified | `unverified (Firebox events)` | Needs verification | verified | [link](https://www.watchguard.com/help/docs/API/Content/en-US/api_get_started/get_started.html) |
| AWS Security Hub / GuardDuty | Cloud security | REST pull (AWS JSON API) | AWS SigV4 | NextToken in the request body | `POST /findings (GetFindings) · GuardDuty ListFindings` | Needs capability: AWS SigV4 request signing | verified | [link](https://docs.aws.amazon.com/goto/WebAPI/guardduty/ListFindings) |
| CrowdStrike Cloud Security | Cloud security | REST pull | OAuth2 client credentials | Query IDs, then fetch entities by ID | `IOM queries + IOM entities (Cloud Security Detections)` | Needs capability: Two-step ID lookup | verified | [link](https://developer.crowdstrike.com/api-reference/collections/cloud-security-detections/) |
| Google Security Command Center | Cloud security | REST pull | OAuth2 via service-account JWT | pageToken / nextPageToken | `GET v2 .../sources/-/findings` | Needs capability: Service-account JWT (Google OAuth2) | partly verified | [link](https://googleapis.github.io/google-api-python-client/docs/dyn/securitycenter_v1.projects.sources.findings.html) |
| Lacework FortiCNAPP | Cloud security | REST pull | Session login (POST /api/v2/access/tokens, X-LW-UAKS + keyId) | Next page URL in the body (paging.urls.nextPage) | `GET /api/v2/Alerts` | Template ready | partly verified | [link](https://docs.fortinet.com/document/forticnapp/latest/api-reference/932048) |
| Orca Security | Cloud security | REST pull (serving-layer query) | API token (Authorization: Token) | In the request body (1000 per page) | `POST /api/serving-layer/query` | Needs capability: Request-body pagination (incl. GraphQL cursors) | partly verified | [link](https://docs.praetorian.com/articles/4095117-orca-security) |
| Prisma Cloud | Cloud security | REST pull | Session login (/login with access key, token in x-redlock-auth) | pageToken | `unverified (alerts list path)` | Needs verification | verified | [link](https://pan.dev/prisma-cloud/api/cspm/prisma-cloud-login-api-overview/) |
| Wiz | Cloud security | GraphQL | OAuth2 client credentials (with audience) | GraphQL cursor (after / pageInfo.endCursor) | `POST /graphql (issues query)` | Needs capability: Request-body pagination (incl. GraphQL cursors) | partly verified | [link](https://www.scribd.com/document/810029023/Using-the-Wiz-API) |

</details>
