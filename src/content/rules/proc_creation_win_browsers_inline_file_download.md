---
title: File Download From Browser Process Via Inline URL
summary: >-
  Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for
  example by launching the browser in a minimized state.
sigma_id: 94771a71-ba41-4b6e-a757-b531372eaab6
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2022-01-11'
modified: '2025-10-27'
falsepositives:
  - Unknown
references:
  - https://twitter.com/mrd0x/status/1478116126005641220
  - https://lolbas-project.github.io/lolbas/Binaries/Msedge/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_browsers_inline_file_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: File Download From Browser Process Via Inline URL
id: 94771a71-ba41-4b6e-a757-b531372eaab6
status: test
description: Detects execution of a browser process with a URL argument pointing to a file with a potentially interesting extension. This can be abused to download arbitrary files or to hide from the user for example by launching the browser in a minimized state.
references:
    - https://twitter.com/mrd0x/status/1478116126005641220
    - https://lolbas-project.github.io/lolbas/Binaries/Msedge/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-01-11
modified: 2025-10-27
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
    selection_http:
        CommandLine|contains: 'http'
    selection_extensions:
        - CommandLine|endswith:
              - '.7z'
              - '.dat'
              - '.dll'
              - '.exe'
              - '.hta'
              - '.ps1'
              - '.psm1'
              - '.txt'
              - '.vbe'
              - '.vbs'
              - '.zip'
        - CommandLine|contains:
              - '.7z"'
              - '.dat"'
              - '.dll"'
              - '.hta"'
              - '.ps1"'
              - '.psm1"'
              - '.txt"'
              - '.vbe"'
              - '.vbs"'
              - '.zip"'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_browsers_inline_file_download/info.yml
```
