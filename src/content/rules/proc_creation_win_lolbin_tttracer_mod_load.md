---
title: Time Travel Debugging Utility Usage
summary: Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.
sigma_id: 0b4ae027-2a2d-4b93-8c7e-962caaba5b2a
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0005
techniques:
  - T1218
  - T1003.001
author: Ensar Şamil, @sblmsrsn, @oscd_initiative
date: '2020-10-06'
modified: '2022-10-09'
falsepositives:
  - Legitimate usage by software developers/testers
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
  - https://web.archive.org/web/20191118131013/https://twitter.com/mattifestation/status/1196390321783025666
  - https://twitter.com/oulusoyum/status/1191329746069655553
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_tttracer_mod_load.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Time Travel Debugging Utility Usage
id: 0b4ae027-2a2d-4b93-8c7e-962caaba5b2a
related:
    - id: e76c8240-d68f-4773-8880-5c6f63595aaf
      type: derived
status: test
description: Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
    - https://web.archive.org/web/20191118131013/https://twitter.com/mattifestation/status/1196390321783025666
    - https://twitter.com/oulusoyum/status/1191329746069655553
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
date: 2020-10-06
modified: 2022-10-09
tags:
    - attack.credential-access
    - attack.stealth
    - attack.t1218
    - attack.t1003.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\tttracer.exe'
    condition: selection
falsepositives:
    - Legitimate usage by software developers/testers
level: high
```
