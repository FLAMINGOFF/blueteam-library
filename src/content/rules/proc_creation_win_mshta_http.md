---
title: Remotely Hosted HTA File Executed Via Mshta.EXE
summary: Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file
sigma_id: b98d0db6-511d-45de-ad02-e82a98729620
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218.005
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-08'
modified: '2023-02-06'
falsepositives:
  - Unknown
references:
  - https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mshta_http.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remotely Hosted HTA File Executed Via Mshta.EXE
id: b98d0db6-511d-45de-ad02-e82a98729620
status: test
description: Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file
references:
    - https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-Virus-scans-log4shell.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-08
modified: 2023-02-06
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\mshta.exe'
        - OriginalFileName: 'MSHTA.EXE'
    selection_cli:
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'ftp://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_mshta_http/info.yml
```
