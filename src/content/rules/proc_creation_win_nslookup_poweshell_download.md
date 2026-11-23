---
title: Nslookup PowerShell Download Cradle - ProcessCreation
summary: |-
  Detects suspicious powershell download cradle using nslookup.
  This cradle uses nslookup to extract payloads from DNS records
sigma_id: 1b3b01c7-84e9-4072-86e5-fc285a41ff23
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1071.004
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-05'
modified: '2026-10-13'
falsepositives:
  - Unknown
references:
  - https://twitter.com/Alh4zr3d/status/1566489367232651264
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_nslookup_poweshell_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Nslookup PowerShell Download Cradle - ProcessCreation
id: 1b3b01c7-84e9-4072-86e5-fc285a41ff23
related:
    - id: 72671447-4352-4413-bb91-b85569687135
      type: obsolete
    - id: 999bff6d-dc15-44c9-9f5c-e1051bfc86e1
      type: similar
status: test
description: |
    Detects suspicious powershell download cradle using nslookup.
    This cradle uses nslookup to extract payloads from DNS records
references:
    - https://twitter.com/Alh4zr3d/status/1566489367232651264
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-05
modified: 2026-10-13
tags:
    - attack.command-and-control
    - attack.t1071.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\nslookup.exe'
        - OriginalFileName: 'nslookup.exe'
    selection_cmd:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' -q=txt '
            - ' -querytype=txt '
            - ' -type=txt'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
