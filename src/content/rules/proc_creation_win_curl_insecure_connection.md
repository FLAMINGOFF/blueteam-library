---
title: Insecure Transfer Via Curl.EXE
summary: Detects execution of "curl.exe" with the "--insecure" flag.
sigma_id: cb9cc1d1-e84e-4bdc-b7ad-c31b1b7908ec
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: X__Junior (Nextron Systems)
date: '2023-06-30'
falsepositives:
  - Access to badly maintained internal or development systems
references:
  - https://curl.se/docs/manpage.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_curl_insecure_connection.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Insecure Transfer Via Curl.EXE
id: cb9cc1d1-e84e-4bdc-b7ad-c31b1b7908ec
status: test
description: Detects execution of "curl.exe" with the "--insecure" flag.
references:
    - https://curl.se/docs/manpage.html
author: X__Junior (Nextron Systems)
date: 2023-06-30
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\curl.exe'
        - OriginalFileName: 'curl.exe'
    selection_cli:
        - CommandLine|re: '\s-k\s'
        - CommandLine|contains: '--insecure'
    condition: all of selection_*
falsepositives:
    - Access to badly maintained internal or development systems
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_curl_insecure_connection/info.yml
```
