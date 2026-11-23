---
title: Suspicious Reg Add BitLocker
summary: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
sigma_id: 0e0255bf-2548-47b8-9582-c0955c9283f5
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1486
author: frack113
date: '2021-11-15'
modified: '2022-09-09'
falsepositives:
  - Unlikely
references:
  - https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_bitlocker.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Reg Add BitLocker
id: 0e0255bf-2548-47b8-9582-c0955c9283f5
status: test
description: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
references:
    - https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
author: frack113
date: 2021-11-15
modified: 2022-09-09
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'REG'
            - 'ADD'
            - '\SOFTWARE\Policies\Microsoft\FVE'
            - '/v'
            - '/f'
        CommandLine|contains:
            - 'EnableBDEWithNoTPM'
            - 'UseAdvancedStartup'
            - 'UseTPM'
            - 'UseTPMKey'
            - 'UseTPMKeyPIN'
            - 'RecoveryKeyMessageSource'
            - 'UseTPMPIN'
            - 'RecoveryKeyMessage'
    condition: selection
falsepositives:
    - Unlikely
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_reg_bitlocker/info.yml
```
