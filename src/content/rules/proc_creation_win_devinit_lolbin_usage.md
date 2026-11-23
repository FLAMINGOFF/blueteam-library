---
title: Arbitrary MSI Download Via Devinit.EXE
summary: Detects a certain command line flag combination used by "devinit.exe", which can be abused as a LOLBIN to download arbitrary MSI packages on a Windows system
sigma_id: 90d50722-0483-4065-8e35-57efaadd354d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1218
author: Florian Roth (Nextron Systems)
date: '2022-01-11'
modified: '2023-04-06'
falsepositives:
  - Unknown
references:
  - https://twitter.com/mrd0x/status/1460815932402679809
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devinit/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_devinit_lolbin_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary MSI Download Via Devinit.EXE
id: 90d50722-0483-4065-8e35-57efaadd354d
status: test
description: Detects a certain command line flag combination used by "devinit.exe", which can be abused as a LOLBIN to download arbitrary MSI packages on a Windows system
references:
    - https://twitter.com/mrd0x/status/1460815932402679809
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devinit/
author: Florian Roth (Nextron Systems)
date: 2022-01-11
modified: 2023-04-06
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' -t msi-install '
            - ' -i http'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
