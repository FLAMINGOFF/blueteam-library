---
title: CMSTP Execution Process Access
summary: Detects various indicators of Microsoft Connection Manager Profile Installer execution
sigma_id: 3b4b232a-af90-427c-a22f-30b0c0837b95
status: stable
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0002
techniques:
  - T1218.003
  - T1559.001
author: Nik Seetharaman
date: '2018-07-16'
modified: '2021-06-27'
falsepositives:
  - Legitimate CMSTP use (unlikely in modern enterprise environments)
references:
  - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_cmstp_execution_by_access.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: CMSTP Execution Process Access
id: 3b4b232a-af90-427c-a22f-30b0c0837b95
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
author: Nik Seetharaman
date: 2018-07-16
modified: 2021-06-27
tags:
    - attack.stealth
    - attack.t1218.003
    - attack.execution
    - attack.t1559.001
    - attack.g0069
    - attack.g0080
    - car.2019-04-001
logsource:
    product: windows
    category: process_access
detection:
    # Process Access Call Trace
    selection:
        CallTrace|contains: 'cmlua.dll'
    condition: selection
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
```
