---
title: Browser Started with Remote Debugging
summary: Detects browsers starting with the remote debugging flags. Which is a technique often used to perform browser injection attacks
sigma_id: b3d34dc5-2efd-4ae3-845f-8ec14921f449
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0009
techniques:
  - T1185
author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-27'
modified: '2022-12-23'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20230420012250/https://yoroi.company/wp-content/uploads/2022/05/EternityGroup_report_compressed.pdf
  - https://www.mdsec.co.uk/2022/10/analysing-lastpass-part-1/
  - https://github.com/defaultnamehere/cookie_crimes/
  - https://github.com/wunderwuzzi23/firefox-cookiemonster
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_browsers_remote_debugging.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Browser Started with Remote Debugging
id: b3d34dc5-2efd-4ae3-845f-8ec14921f449
related:
    - id: 3e8207c5-fcd2-4ea6-9418-15d45b4890e4
      type: derived
status: test
description: Detects browsers starting with the remote debugging flags. Which is a technique often used to perform browser injection attacks
references:
    - https://web.archive.org/web/20230420012250/https://yoroi.company/wp-content/uploads/2022/05/EternityGroup_report_compressed.pdf
    - https://www.mdsec.co.uk/2022/10/analysing-lastpass-part-1/
    - https://github.com/defaultnamehere/cookie_crimes/
    - https://github.com/wunderwuzzi23/firefox-cookiemonster
author: pH-T (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-27
modified: 2022-12-23
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1185
logsource:
    category: process_creation
    product: windows
detection:
    selection_chromium_based:
        # Covers: --remote-debugging-address, --remote-debugging-port, --remote-debugging-socket-name, --remote-debugging-pipe....etc
        CommandLine|contains: ' --remote-debugging-'
    selection_firefox:
        Image|endswith: '\firefox.exe'
        CommandLine|contains: ' -start-debugger-server'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
```
