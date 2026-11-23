---
title: Potential Data Stealing Via Chromium Headless Debugging
summary: Detects chromium based browsers starting in headless and debugging mode and pointing to a user profile. This could be a sign of data stealing or remote control
sigma_id: 3e8207c5-fcd2-4ea6-9418-15d45b4890e4
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0009
techniques:
  - T1185
  - T1564.003
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-12-23'
falsepositives:
  - Unknown
references:
  - https://github.com/defaultnamehere/cookie_crimes/
  - https://mango.pdf.zone/stealing-chrome-cookies-without-a-password
  - https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/
  - https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_debugging.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Data Stealing Via Chromium Headless Debugging
id: 3e8207c5-fcd2-4ea6-9418-15d45b4890e4
related:
    - id: b3d34dc5-2efd-4ae3-845f-8ec14921f449
      type: derived
status: test
description: Detects chromium based browsers starting in headless and debugging mode and pointing to a user profile. This could be a sign of data stealing or remote control
references:
    - https://github.com/defaultnamehere/cookie_crimes/
    - https://mango.pdf.zone/stealing-chrome-cookies-without-a-password
    - https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/
    - https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-23
tags:
    - attack.credential-access
    - attack.collection
    - attack.stealth
    - attack.t1185
    - attack.t1564.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '--remote-debugging-' # Covers: --remote-debugging-address, --remote-debugging-port, --remote-debugging-socket-name, --remote-debugging-pipe....etc
            - '--user-data-dir'
            - '--headless'
    condition: selection
falsepositives:
    - Unknown
level: high
```
