---
title: Suspicious Process Created Via Wmic.EXE
summary: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.
sigma_id: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1047
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2020-10-12'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2020/10/08/ryuks-return/
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Process Created Via Wmic.EXE
id: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
related:
    - id: 526be59f-a573-4eea-b5f7-f0973207634d # Generic
      type: derived
status: test
description: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.
references:
    - https://thedfirreport.com/2020/10/08/ryuks-return/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2020-10-12
modified: 2023-02-14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'process '
            - 'call '
            - 'create '
        CommandLine|contains:
            # Add more susupicious paths and binaries as you see fit in your env
            - 'rundll32'
            - 'bitsadmin'
            - 'regsvr32'
            - 'cmd.exe /c '
            - 'cmd.exe /k '
            - 'cmd.exe /r '
            - 'cmd /c '
            - 'cmd /k '
            - 'cmd /r '
            - 'powershell'
            - 'pwsh'
            - 'certutil'
            - 'cscript'
            - 'wscript'
            - 'mshta'
            - '\Users\Public\'
            - '\Windows\Temp\'
            - '\AppData\Local\'
            - '%temp%'
            - '%tmp%'
            - '%ProgramData%'
            - '%appdata%'
            - '%comspec%'
            - '%localappdata%'
    condition: selection
falsepositives:
    - Unknown
level: high
simulation:
    - type: atomic red team
      name: WMI Execute rundll32
      technique: T1047
      atomic_guid: 00738d2a-4651-4d76-adf2-c43a41dfb243
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation/info.yml
```
