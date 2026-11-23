---
title: Suspicious PowerShell Invocation From Script Engines
summary: Detects suspicious powershell invocations from interpreters or unusual programs
sigma_id: 95eadcb2-92e4-4ed1-9031-92547773a6db
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: Florian Roth (Nextron Systems)
date: '2019-01-16'
modified: '2023-01-05'
falsepositives:
  - Microsoft Operations Manager (MOM)
  - Other scripts
references:
  - https://www.securitynewspaper.com/2017/03/20/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_script_engine_parent.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious PowerShell Invocation From Script Engines
id: 95eadcb2-92e4-4ed1-9031-92547773a6db
status: test
description: Detects suspicious powershell invocations from interpreters or unusual programs
references:
    - https://www.securitynewspaper.com/2017/03/20/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2023-01-05
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_health_service:
        CurrentDirectory|contains: '\Health Service State\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Microsoft Operations Manager (MOM)
    - Other scripts
level: medium
```
