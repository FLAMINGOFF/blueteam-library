---
title: Use of Remote.exe
summary: Remote.exe is part of WinDbg in the Windows SDK and can be used for AWL bypass and running remote files.
sigma_id: 4eddc365-79b4-43ff-a9d7-99422dc34b93
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
date: '2022-06-02'
falsepositives:
  - Approved installs of Windows SDK with Debugging Tools for Windows (WinDbg).
references:
  - https://web.archive.org/web/20210922181157/https://blog.thecybersecuritytutor.com/Exeuction-AWL-Bypass-Remote-exe-LOLBin/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Remote/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_remote.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of Remote.exe
id: 4eddc365-79b4-43ff-a9d7-99422dc34b93
status: test
description: Remote.exe is part of WinDbg in the Windows SDK and can be used for AWL bypass and running remote files.
references:
    - https://web.archive.org/web/20210922181157/https://blog.thecybersecuritytutor.com/Exeuction-AWL-Bypass-Remote-exe-LOLBin/
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Remote/
author: 'Christopher Peacock @SecurePeacock, SCYTHE @scythe_io'
date: 2022-06-02
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\remote.exe'
        - OriginalFileName: 'remote.exe'
    condition: selection
falsepositives:
    - Approved installs of Windows SDK with Debugging Tools for Windows (WinDbg).
level: medium
```
