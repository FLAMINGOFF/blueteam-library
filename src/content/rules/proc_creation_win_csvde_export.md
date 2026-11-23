---
title: Active Directory Structure Export Via Csvde.EXE
summary: Detects the execution of "csvde.exe" in order to export organizational Active Directory structure.
sigma_id: e5d36acd-acb4-4c6f-a13f-9eb203d50099
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0010
  - TA0007
techniques:
  - T1087.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-03-14'
falsepositives:
  - Unknown
references:
  - https://www.cybereason.com/blog/research/operation-ghostshell-novel-rat-targets-global-aerospace-and-telecoms-firms
  - https://web.archive.org/web/20180725233601/https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
  - https://businessinsights.bitdefender.com/deep-dive-into-a-backdoordiplomacy-attack-a-study-of-an-attackers-toolkit
  - https://redcanary.com/blog/msix-installers/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_csvde_export.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Active Directory Structure Export Via Csvde.EXE
id: e5d36acd-acb4-4c6f-a13f-9eb203d50099
status: test
description: Detects the execution of "csvde.exe" in order to export organizational Active Directory structure.
references:
    - https://www.cybereason.com/blog/research/operation-ghostshell-novel-rat-targets-global-aerospace-and-telecoms-firms
    - https://web.archive.org/web/20180725233601/https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
    - https://businessinsights.bitdefender.com/deep-dive-into-a-backdoordiplomacy-attack-a-study-of-an-attackers-toolkit
    - https://redcanary.com/blog/msix-installers/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-14
tags:
    - attack.exfiltration
    - attack.discovery
    - attack.t1087.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\csvde.exe'
        - OriginalFileName: 'csvde.exe'
    selection_remote:
        CommandLine|contains: ' -f'
    filter_import:
        CommandLine|contains: ' -i'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
```
