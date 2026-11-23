---
title: Suspicious ArcSOC.exe Child Process
summary: |-
  Detects script interpreters, command-line tools, and similar suspicious child processes of ArcSOC.exe.
  ArcSOC.exe is the process name which hosts ArcGIS Server REST services. If an attacker compromises an ArcGIS
  Server system and uploads a malicious Server Object Extension (SOE), they can send crafted requests to the corresponding
  service endpoint and remotely execute code from the ArcSOC.exe process.
sigma_id: 8e95e73e-ba02-4a87-b4d7-0929b8053038
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
  - T1203
author: Micah Babinski
date: '2025-11-25'
falsepositives:
  - Unknown
references:
  - https://reliaquest.com/blog/threat-spotlight-inside-flax-typhoons-arcgis-compromise/
  - https://enterprise.arcgis.com/en/server/12.0/administer/windows/inside-an-arcgis-server-site.htm
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_arcsoc_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious ArcSOC.exe Child Process
id: 8e95e73e-ba02-4a87-b4d7-0929b8053038
status: experimental
description: |
    Detects script interpreters, command-line tools, and similar suspicious child processes of ArcSOC.exe.
    ArcSOC.exe is the process name which hosts ArcGIS Server REST services. If an attacker compromises an ArcGIS
    Server system and uploads a malicious Server Object Extension (SOE), they can send crafted requests to the corresponding
    service endpoint and remotely execute code from the ArcSOC.exe process.
references:
    - https://reliaquest.com/blog/threat-spotlight-inside-flax-typhoons-arcgis-compromise/
    - https://enterprise.arcgis.com/en/server/12.0/administer/windows/inside-an-arcgis-server-site.htm
author: Micah Babinski
date: 2025-11-25
tags:
    - attack.execution
    - attack.t1059
    - attack.t1203
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\ArcSOC.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    filter_main_cmd:
        Image|endswith: '\cmd.exe'
        CommandLine: 'cmd.exe /c "ver"'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
