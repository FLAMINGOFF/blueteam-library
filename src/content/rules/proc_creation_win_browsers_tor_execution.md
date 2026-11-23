---
title: Tor Client/Browser Execution
summary: Detects the use of Tor or Tor-Browser to connect to onion routing networks
sigma_id: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1090.003
author: frack113
date: '2022-02-20'
modified: '2025-10-27'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20260310035047/https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_browsers_tor_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Tor Client/Browser Execution
id: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c
status: test
description: Detects the use of Tor or Tor-Browser to connect to onion routing networks
references:
    - https://web.archive.org/web/20260310035047/https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
author: frack113
date: 2022-02-20
modified: 2025-10-27
tags:
    - attack.command-and-control
    - attack.t1090.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: 'Tor Browser'
        - Product: 'Tor Browser'
        - Image|endswith:
              - '\tor.exe'
              - '\Tor Browser\Browser\firefox.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_browsers_tor_execution/info.yml
```
