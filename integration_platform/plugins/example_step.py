"""Example `custom_step` plugin.

Use a custom step only for the rare case that declarative config cannot express. A custom step is any class
with a `process(records, config) -> records` method. It runs on the raw records after fetching and before
mapping. Reference it from a config as:

    custom_step: "integration_platform.plugins.example_step.KevSeverity"

This one derives a severity for CISA KEV entries (which have none) from a conditional rule:
ransomware-linked CVEs become "critical", everything else "high". See configs/examples/cisa_kev.yaml.
"""
from __future__ import annotations

from typing import Any


class KevSeverity:
    def process(self, records: list[dict[str, Any]], config: Any) -> list[dict[str, Any]]:
        for record in records:
            record["derived_severity"] = "critical" if record.get("knownRansomwareCampaignUse") == "Known" else "high"
        return records
