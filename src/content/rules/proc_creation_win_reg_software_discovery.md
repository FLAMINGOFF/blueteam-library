---
title: Detected Windows Software Discovery
summary: >-
  Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is
  vulnerable.
sigma_id: e13f668e-7f95-443d-98d2-1816a7648a7b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1518
author: Nikita Nazarov, oscd.community
date: '2020-10-16'
modified: '2022-10-09'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518/T1518.md
  - https://github.com/harleyQu1nn/AggressorScripts
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_software_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Detected Windows Software Discovery
id: e13f668e-7f95-443d-98d2-1816a7648a7b
related:
    - id: 2650dd1a-eb2a-412d-ac36-83f06c4f2282
      type: derived
status: test
description: Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518/T1518.md
    - https://github.com/harleyQu1nn/AggressorScripts # AVQuery.cna
author: Nikita Nazarov, oscd.community
date: 2020-10-16
modified: 2022-10-09
tags:
    - attack.discovery
    - attack.t1518
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'    # Example: reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion
        CommandLine|contains|all:
            - 'query'
            - '\software\'
            - '/v'
            - 'svcversion'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
