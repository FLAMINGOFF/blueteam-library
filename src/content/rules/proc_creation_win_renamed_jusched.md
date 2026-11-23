---
title: Renamed Jusched.EXE Execution
summary: Detects the execution of a renamed "jusched.exe" as seen used by the cobalt group
sigma_id: edd8a48c-1b9f-4ba1-83aa-490338cd1ccb
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1036.003
author: Markus Neis, Swisscom
date: '2019-06-04'
modified: '2023-02-03'
falsepositives:
  - Unknown
references:
  - https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_jusched.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Jusched.EXE Execution
id: edd8a48c-1b9f-4ba1-83aa-490338cd1ccb
status: test
description: Detects the execution of a renamed "jusched.exe" as seen used by the cobalt group
references:
    - https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf
author: Markus Neis, Swisscom
date: 2019-06-04
modified: 2023-02-03
tags:
    - attack.execution
    - attack.stealth
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description:
            - Java Update Scheduler
            - Java(TM) Update Scheduler
    filter:
        Image|endswith: '\jusched.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
