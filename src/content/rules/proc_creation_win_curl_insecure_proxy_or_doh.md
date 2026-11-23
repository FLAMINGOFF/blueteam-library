---
title: Insecure Proxy/DOH Transfer Via Curl.EXE
summary: Detects execution of "curl.exe" with the "insecure" flag over proxy or DOH.
sigma_id: 2c1486f5-02e8-4f86-9099-b97f2da4ed77
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
  - Access to badly maintained internal or development systems
references:
  - https://curl.se/docs/manpage.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_curl_insecure_proxy_or_doh.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Insecure Proxy/DOH Transfer Via Curl.EXE
id: 2c1486f5-02e8-4f86-9099-b97f2da4ed77
status: test
description: Detects execution of "curl.exe" with the "insecure" flag over proxy or DOH.
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
        CommandLine|contains:
            - '--doh-insecure'
            - '--proxy-insecure'
    condition: all of selection_*
falsepositives:
    - Access to badly maintained internal or development systems
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_curl_insecure_proxy_or_doh/info.yml
```
