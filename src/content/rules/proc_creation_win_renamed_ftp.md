---
title: Renamed FTP.EXE Execution
summary: Detects the execution of a renamed "ftp.exe" binary based on the PE metadata fields
sigma_id: 277a4393-446c-449a-b0ed-7fdc7795244c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
  - T1202
author: Victor Sergeev, oscd.community
date: '2020-10-09'
modified: '2023-02-03'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ftp/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_ftp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed FTP.EXE Execution
id: 277a4393-446c-449a-b0ed-7fdc7795244c
status: test
description: Detects the execution of a renamed "ftp.exe" binary based on the PE metadata fields
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ftp/
author: Victor Sergeev, oscd.community
date: 2020-10-09
modified: 2023-02-03
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_original:
        OriginalFileName: 'ftp.exe'
    filter_img:
        Image|endswith: '\ftp.exe'
    condition: selection_original and not filter_img
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_renamed_ftp/info.yml
```
