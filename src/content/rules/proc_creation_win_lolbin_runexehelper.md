---
title: Lolbin Runexehelper Use As Proxy
summary: Detect usage of the "runexehelper.exe" binary as a proxy to launch other programs
sigma_id: cd71385d-fd9b-4691-9b98-2b1f7e508714
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: frack113
date: '2022-12-29'
falsepositives:
  - Unknown
references:
  - https://twitter.com/0gtweet/status/1206692239839289344
  - https://lolbas-project.github.io/lolbas/Binaries/Runexehelper/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_runexehelper.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Lolbin Runexehelper Use As Proxy
id: cd71385d-fd9b-4691-9b98-2b1f7e508714
status: test
description: Detect usage of the "runexehelper.exe" binary as a proxy to launch other programs
references:
    - https://twitter.com/0gtweet/status/1206692239839289344
    - https://lolbas-project.github.io/lolbas/Binaries/Runexehelper/
author: frack113
date: 2022-12-29
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\runexehelper.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
