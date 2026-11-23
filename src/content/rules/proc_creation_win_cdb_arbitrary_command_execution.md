---
title: Potential Binary Proxy Execution Via Cdb.EXE
summary: Detects usage of "cdb.exe" to launch arbitrary processes or commands from a debugger script file
sigma_id: b5c7395f-e501-4a08-94d4-57fe7a9da9d2
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1106
  - T1218
  - T1127
author: Beyu Denis, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: '2019-10-26'
modified: '2024-04-22'
falsepositives:
  - Legitimate use of debugging tools
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Cdb/
  - https://web.archive.org/web/20170715043507/http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
  - https://twitter.com/nas_bench/status/1534957360032120833
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cdb_arbitrary_command_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Binary Proxy Execution Via Cdb.EXE
id: b5c7395f-e501-4a08-94d4-57fe7a9da9d2
status: test
description: Detects usage of "cdb.exe" to launch arbitrary processes or commands from a debugger script file
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Cdb/
    - https://web.archive.org/web/20170715043507/http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
    - https://twitter.com/nas_bench/status/1534957360032120833
author: Beyu Denis, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-26
modified: 2024-04-22
tags:
    - attack.execution
    - attack.stealth
    - attack.t1106
    - attack.t1218
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cdb.exe'
        - OriginalFileName: 'CDB.Exe'
    selection_cli:
        CommandLine|contains:
            - ' -c ' # Using a debugger script
            - ' -cf '
    condition: all of selection*
falsepositives:
    - Legitimate use of debugging tools
level: medium
```
