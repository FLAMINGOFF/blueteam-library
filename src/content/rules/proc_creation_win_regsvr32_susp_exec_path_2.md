---
title: Regsvr32 Execution From Highly Suspicious Location
summary: Detects execution of regsvr32 where the DLL is located in a highly suspicious locations
sigma_id: 327ff235-94eb-4f06-b9de-aaee571324be
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.010
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-26'
falsepositives:
  - Unlikely
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_2.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Regsvr32 Execution From Highly Suspicious Location
id: 327ff235-94eb-4f06-b9de-aaee571324be
status: test
description: Detects execution of regsvr32 where the DLL is located in a highly suspicious locations
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-26
tags:
    - attack.stealth
    - attack.t1218.010
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regsvr32.exe'
        - OriginalFileName: 'REGSVR32.EXE'
    selection_path_1:
        CommandLine|contains:
            - ':\PerfLogs\'
            - ':\Temp\'
            - '\Windows\Registration\CRMLog'
            - '\Windows\System32\com\dmp\'
            - '\Windows\System32\FxsTmp\'
            - '\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\'
            - '\Windows\System32\spool\drivers\color\'
            - '\Windows\System32\spool\PRINTERS\'
            - '\Windows\System32\spool\SERVERS\'
            - '\Windows\System32\Tasks_Migrated\'
            - '\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\'
            - '\Windows\SysWOW64\com\dmp\'
            - '\Windows\SysWOW64\FxsTmp\'
            - '\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\'
            - '\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\'
            - '\Windows\Tasks\'
            - '\Windows\Tracing\'
    selection_path_2:
        CommandLine|contains:
            # This is to avoid collisions with CLI starting with "C:\"
            - ' "C:\'
            - ' C:\'
            - " 'C:\\"
            - 'D:\'
    selection_exclude_known_dirs:
        CommandLine|contains:
            # Note: add additional locations that are related to third party applications
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\ProgramData\'
            - 'C:\Users\'
            # Note: The space added here are to avoid collisions with the "regsvr32" binary full path
            - ' C:\Windows\'
            - ' "C:\Windows\'
            - " 'C:\\Windows\\"
    filter_main_empty:
        CommandLine: ''
    filter_main_null:
        CommandLine: null
    condition: selection_img and (selection_path_1 or (selection_path_2 and not selection_exclude_known_dirs)) and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
