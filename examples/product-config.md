# Product Configuration — ACME Infusion Pump v2.0

This file drives **cra-cli**: it tells the tool which component SBOMs
make up the product and how to triage known vulnerabilities.

## SBOM Manifest

| Component Name | Path                          | Description                        |
|----------------|-------------------------------|------------------------------------|
| Frontend       | sboms/frontend.spdx.json      | React-based admin dashboard        |
| Backend        | sboms/backend.spdx.json       | Python API service                 |
| Firmware       | sboms/firmware.spdx.json      | Embedded C firmware for the device |

## VEX Triage

| CVE ID           | Status              | Justification                              | Impact                                     |
|------------------|----------------------|--------------------------------------------|--------------------------------------------|
| CVE-2021-44228   | known_not_affected   | vulnerable_code_not_in_execute_path        | Log4j is included but JNDI is disabled     |
| CVE-2023-44487   | known_affected       |                                            | HTTP/2 rapid-reset — upgrade planned Q3    |
| CVE-2024-3094    | known_not_affected   | component_not_present                      | xz-utils not shipped in our build          |
