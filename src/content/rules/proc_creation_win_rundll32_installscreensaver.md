---
title: Rundll32 InstallScreenSaver Execution
summary: An attacker may execute an application as a SCR File using rundll32.exe desk.cpl,InstallScreenSaver
sigma_id: 15bd98ea-55f4-4d37-b09a-e7caa0fa2221
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.011
author: Christopher Peacock @securepeacock, SCYTHE @scythe_io, TactiKoolSec
date: '2022-04-28'
modified: '2023-02-09'
falsepositives:
  - Legitimate installation of a new screensaver
references:
  - https://lolbas-project.github.io/lolbas/Libraries/Desk/
  - https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1218.011/T1218.011.md#atomic-test-13---rundll32-with-deskcpl
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_installscreensaver.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Rundll32 InstallScreenSaver Execution
id: 15bd98ea-55f4-4d37-b09a-e7caa0fa2221
status: test
description: An attacker may execute an application as a SCR File using rundll32.exe desk.cpl,InstallScreenSaver
references:
    - https://lolbas-project.github.io/lolbas/Libraries/Desk/
    - https://github.com/redcanaryco/atomic-red-team/blob/0f229c0e42bfe7ca736a14023836d65baa941ed2/atomics/T1218.011/T1218.011.md#atomic-test-13---rundll32-with-deskcpl
author: 'Christopher Peacock @securepeacock, SCYTHE @scythe_io, TactiKoolSec'
date: 2022-04-28
modified: 2023-02-09
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains: 'InstallScreenSaver'
    condition: all of selection_*
falsepositives:
    - Legitimate installation of a new screensaver
level: medium
```
