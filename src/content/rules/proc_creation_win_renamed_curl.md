---
title: Renamed CURL.EXE Execution
summary: Detects the execution of a renamed "CURL.exe" binary based on the PE metadata fields
sigma_id: 7530cd3d-7671-43e3-b209-976966f6ea48
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1059
  - T1202
author: X__Junior (Nextron Systems)
date: '2023-09-11'
modified: '2023-10-12'
falsepositives:
  - Unknown
references:
  - https://twitter.com/Kostastsale/status/1700965142828290260
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_curl.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed CURL.EXE Execution
id: 7530cd3d-7671-43e3-b209-976966f6ea48
status: test
description: Detects the execution of a renamed "CURL.exe" binary based on the PE metadata fields
references:
    - https://twitter.com/Kostastsale/status/1700965142828290260
author: X__Junior (Nextron Systems)
date: 2023-09-11
modified: 2023-10-12
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'curl.exe'
        - Description: 'The curl executable'
    filter_main_img:
        Image|contains: '\curl'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_renamed_curl/info.yml
```
