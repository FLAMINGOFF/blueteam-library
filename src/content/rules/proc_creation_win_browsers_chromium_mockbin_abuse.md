---
title: Chromium Browser Headless Execution To Mockbin Like Site
summary: Detects the execution of a Chromium based browser process with the "headless" flag and a URL pointing to the mockbin.org service (which can be used to exfiltrate data).
sigma_id: 1c526788-0abe-4713-862f-b520da5e5316
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: X__Junior (Nextron Systems)
date: '2023-09-11'
falsepositives:
  - Unknown
references:
  - https://www.zscaler.com/blogs/security-research/steal-it-campaign
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_browsers_chromium_mockbin_abuse.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Chromium Browser Headless Execution To Mockbin Like Site
id: 1c526788-0abe-4713-862f-b520da5e5316
status: test
description: Detects the execution of a Chromium based browser process with the "headless" flag and a URL pointing to the mockbin.org service (which can be used to exfiltrate data).
references:
    - https://www.zscaler.com/blogs/security-research/steal-it-campaign
author: X__Junior (Nextron Systems)
date: 2023-09-11
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
    selection_headless:
        CommandLine|contains: '--headless'
    selection_url:
        CommandLine|contains:
            - '://run.mocky'
            - '://mockbin'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_browsers_chromium_mockbin_abuse/info.yml
```
