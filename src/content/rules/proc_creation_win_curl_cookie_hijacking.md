---
title: Potential Cookies Session Hijacking
summary: Detects execution of "curl.exe" with the "-c" flag in order to save cookie data.
sigma_id: 5a6e1e16-07de-48d8-8aae-faa766c05e88
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-07-27'
falsepositives:
  - Unknown
references:
  - https://curl.se/docs/manpage.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_curl_cookie_hijacking.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Cookies Session Hijacking
id: 5a6e1e16-07de-48d8-8aae-faa766c05e88
status: test
description: Detects execution of "curl.exe" with the "-c" flag in order to save cookie data.
references:
    - https://curl.se/docs/manpage.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-07-27
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
        - CommandLine|re: '\s-c\s'
        - CommandLine|contains: '--cookie-jar'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_curl_cookie_hijacking/info.yml
```
