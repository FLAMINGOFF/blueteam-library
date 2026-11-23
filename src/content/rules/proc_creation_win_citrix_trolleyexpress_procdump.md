---
title: Process Access via TrolleyExpress Exclusion
summary: Detects a possible process memory dump that uses the white-listed Citrix TrolleyExpress.exe filename as a way to dump the lsass process memory
sigma_id: 4c0aaedc-154c-4427-ada0-d80ef9c9deb6
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0006
techniques:
  - T1218.011
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2022-02-10'
modified: '2022-05-13'
falsepositives:
  - Unknown
references:
  - https://twitter.com/_xpn_/status/1491557187168178176
  - https://www.youtube.com/watch?v=Ie831jF0bb0
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_citrix_trolleyexpress_procdump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Process Access via TrolleyExpress Exclusion
id: 4c0aaedc-154c-4427-ada0-d80ef9c9deb6
status: test
description: Detects a possible process memory dump that uses the white-listed Citrix TrolleyExpress.exe filename as a way to dump the lsass process memory
references:
    - https://twitter.com/_xpn_/status/1491557187168178176
    - https://www.youtube.com/watch?v=Ie831jF0bb0
author: Florian Roth (Nextron Systems)
date: 2022-02-10
modified: 2022-05-13
tags:
    - attack.stealth
    - attack.t1218.011
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
      # We assume that the lsass.exe process has a process ID that's between 700 and 999 and the dumper uses just the PID as parameter
            - '\TrolleyExpress 7'
            - '\TrolleyExpress 8'
            - '\TrolleyExpress 9'
            - '\TrolleyExpress.exe 7'
            - '\TrolleyExpress.exe 8'
            - '\TrolleyExpress.exe 9'
      # Common dumpers
            - '\TrolleyExpress.exe -ma '
    renamed:
        Image|endswith: '\TrolleyExpress.exe'
    filter_renamed:
        OriginalFileName|contains: 'CtxInstall'
    filter_empty:
        OriginalFileName: null
    condition: selection or ( renamed and not 1 of filter* )
falsepositives:
    - Unknown
level: high
```
