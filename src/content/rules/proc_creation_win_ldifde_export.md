---
title: Active Directory Structure Export Via Ldifde.EXE
summary: Detects the execution of "ldifde.exe" in order to export organizational Active Directory structure.
sigma_id: 4f7a6757-ff79-46db-9687-66501a02d9ec
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0010
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-03-14'
falsepositives:
  - Unknown
references:
  - https://businessinsights.bitdefender.com/deep-dive-into-a-backdoordiplomacy-attack-a-study-of-an-attackers-toolkit
  - https://www.documentcloud.org/documents/5743766-Global-Threat-Report-2019.html
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ldifde_export.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Active Directory Structure Export Via Ldifde.EXE
id: 4f7a6757-ff79-46db-9687-66501a02d9ec
status: test
description: Detects the execution of "ldifde.exe" in order to export organizational Active Directory structure.
references:
    - https://businessinsights.bitdefender.com/deep-dive-into-a-backdoordiplomacy-attack-a-study-of-an-attackers-toolkit
    - https://www.documentcloud.org/documents/5743766-Global-Threat-Report-2019.html
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-14
tags:
    - attack.exfiltration
logsource:
    category: process_creation
    product: windows
detection:
    selection_ldif:
        - Image|endswith: '\ldifde.exe'
        - OriginalFileName: 'ldifde.exe'
    selection_cmd:
        CommandLine|contains: '-f'
    filter_import:
        CommandLine|contains: ' -i'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
```
