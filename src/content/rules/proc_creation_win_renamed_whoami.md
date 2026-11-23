---
title: Renamed Whoami Execution
summary: Detects the execution of whoami that has been renamed to a different name to avoid detection
sigma_id: f1086bf7-a0c4-4a37-9102-01e573caf4a0
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1033
author: Florian Roth (Nextron Systems)
date: '2021-08-12'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
  - https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_whoami.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Whoami Execution
id: f1086bf7-a0c4-4a37-9102-01e573caf4a0
status: test
description: Detects the execution of whoami that has been renamed to a different name to avoid detection
references:
    - https://brica.de/alerts/alert/public/1247926/agent-tesla-keylogger-delivered-inside-a-power-iso-daa-archive/
    - https://app.any.run/tasks/7eaba74e-c1ea-400f-9c17-5e30eee89906/
author: Florian Roth (Nextron Systems)
date: 2021-08-12
modified: 2022-10-09
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'whoami.exe'
    filter:
        Image|endswith: '\whoami.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical
```
