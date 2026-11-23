---
title: Suspicious RASdial Activity
summary: Detects suspicious process related to rasdial.exe
sigma_id: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: juju4
date: '2019-01-16'
modified: '2021-11-27'
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
references:
  - https://twitter.com/subTee/status/891298217907830785
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rasdial_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious RASdial Activity
id: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e
status: test
description: Detects suspicious process related to rasdial.exe
references:
    - https://twitter.com/subTee/status/891298217907830785
author: juju4
date: 2019-01-16
modified: 2021-11-27
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'rasdial.exe'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```
