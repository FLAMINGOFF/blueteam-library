---
title: Scheduled Task/Job At
summary: |-
  Detects the use of at/atd which are utilities that are used to schedule tasks.
  They are often abused by adversaries to maintain persistence or to perform task scheduling for initial or recurring execution of malicious code
sigma_id: d2d642d7-b393-43fe-bae4-e81ed5915c4b
status: stable
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0004
  - TA0002
  - TA0003
techniques:
  - T1053.002
author: Ömer Günal, oscd.community
date: '2020-10-06'
modified: '2022-07-07'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.002/T1053.002.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_at_command.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Scheduled Task/Job At
id: d2d642d7-b393-43fe-bae4-e81ed5915c4b
status: stable
description: |
  Detects the use of at/atd which are utilities that are used to schedule tasks.
  They are often abused by adversaries to maintain persistence or to perform task scheduling for initial or recurring execution of malicious code
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.002/T1053.002.md
author: Ömer Günal, oscd.community
date: 2020-10-06
modified: 2022-07-07
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/at'
            - '/atd'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
```
