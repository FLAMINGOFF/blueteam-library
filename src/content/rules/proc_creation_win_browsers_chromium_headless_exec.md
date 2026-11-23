---
title: Browser Execution In Headless Mode
summary: Detects execution of Chromium based browser in headless mode
sigma_id: ef9dcfed-690c-4c5d-a9d1-482cd422225c
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
  - T1564.003
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-09-12'
falsepositives:
  - Unknown
references:
  - https://twitter.com/mrd0x/status/1478234484881436672?s=12
  - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Browser Execution In Headless Mode
id: ef9dcfed-690c-4c5d-a9d1-482cd422225c
related:
    - id: 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e
      type: derived
status: test
description: Detects execution of Chromium based browser in headless mode
references:
    - https://twitter.com/mrd0x/status/1478234484881436672?s=12
    - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-12
tags:
    - attack.command-and-control
    - attack.stealth
    - attack.t1105
    - attack.t1564.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
        CommandLine|contains: '--headless'
    condition: selection
falsepositives:
    - Unknown
level: low
```
