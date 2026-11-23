---
title: HackTool - Impacket Tools Execution
summary: Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives)
sigma_id: 4627c6ae-6899-46e2-aa0c-6ebcb1becd19
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
  - TA0002
  - TA0006
techniques:
  - T1557.001
author: Florian Roth (Nextron Systems)
date: '2021-07-24'
modified: '2023-02-07'
falsepositives:
  - Legitimate use of the impacket tools
references:
  - https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_impacket_tools.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Impacket Tools Execution
id: 4627c6ae-6899-46e2-aa0c-6ebcb1becd19
status: test
description: Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives)
references:
    - https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries
author: Florian Roth (Nextron Systems)
date: 2021-07-24
modified: 2023-02-07
tags:
    - attack.collection
    - attack.execution
    - attack.credential-access
    - attack.t1557.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|contains:
              - '\goldenPac'
              - '\karmaSMB'
              - '\kintercept'
              - '\ntlmrelayx'
              - '\rpcdump'
              - '\samrdump'
              - '\secretsdump'
              - '\smbexec'
              - '\smbrelayx'
              - '\wmiexec'
              - '\wmipersist'
        - Image|endswith:
              - '\atexec_windows.exe'
              - '\dcomexec_windows.exe'
              - '\dpapi_windows.exe'
              - '\findDelegation_windows.exe'
              - '\GetADUsers_windows.exe'
              - '\GetNPUsers_windows.exe'
              - '\getPac_windows.exe'
              - '\getST_windows.exe'
              - '\getTGT_windows.exe'
              - '\GetUserSPNs_windows.exe'
              - '\ifmap_windows.exe'
              - '\mimikatz_windows.exe'
              - '\netview_windows.exe'
              - '\nmapAnswerMachine_windows.exe'
              - '\opdump_windows.exe'
              - '\psexec_windows.exe'
              - '\rdp_check_windows.exe'
              - '\sambaPipe_windows.exe'
              - '\smbclient_windows.exe'
              - '\smbserver_windows.exe'
              - '\sniff_windows.exe'
              - '\sniffer_windows.exe'
              - '\split_windows.exe'
              - '\ticketer_windows.exe'
              # - '\addcomputer_windows.exe'
              # - '\esentutl_windows.exe'
              # - '\getArch_windows.exe'
              # - '\lookupsid_windows.exe'
              # - '\mqtt_check_windows.exe'
              # - '\mssqlclient_windows.exe'
              # - '\mssqlinstance_windows.exe'
              # - '\ntfs-read_windows.exe'
              # - '\ping_windows.exe'
              # - '\ping6_windows.exe'
              # - '\raiseChild_windows.exe'
              # - '\reg_windows.exe'
              # - '\registry-read_windows.exe'
              # - '\services_windows.exe'
              # - '\wmiquery_windows.exe'
    condition: selection
falsepositives:
    - Legitimate use of the impacket tools
level: high
```
