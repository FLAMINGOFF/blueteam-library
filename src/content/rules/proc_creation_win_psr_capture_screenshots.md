---
title: Screen Capture Activity Via Psr.EXE
summary: Detects execution of Windows Problem Steps Recorder (psr.exe), a utility used to record the user screen and clicks.
sigma_id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1113
author: Beyu Denis, oscd.community
date: '2019-10-12'
modified: '2024-01-04'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Psr/
  - https://web.archive.org/web/20200229201156/https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493861893.pdf
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_psr_capture_screenshots.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Screen Capture Activity Via Psr.EXE
id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: test
description: Detects execution of Windows Problem Steps Recorder (psr.exe), a utility used to record the user screen and clicks.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Psr/
    - https://web.archive.org/web/20200229201156/https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493861893.pdf
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: Beyu Denis, oscd.community
date: 2019-10-12
modified: 2024-01-04
tags:
    - attack.collection
    - attack.t1113
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Psr.exe'
        CommandLine|contains:
            - '/start'
            - '-start'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
