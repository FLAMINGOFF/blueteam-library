---
title: Suspicious Debugger Registration Cmdline
summary: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
sigma_id: ae215552-081e-44c7-805f-be16f975c8a2
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
techniques:
  - T1546.008
author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
date: '2019-09-06'
modified: '2022-08-06'
falsepositives:
  - Unknown
references:
  - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
  - https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_registry_install_reg_debugger_backdoor.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Debugger Registration Cmdline
id: ae215552-081e-44c7-805f-be16f975c8a2
status: test
description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
    - https://bazaar.abuse.ch/sample/6f3aa9362d72e806490a8abce245331030d1ab5ac77e400dd475748236a6cc81/
author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
date: 2019-09-06
modified: 2022-08-06
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546.008
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: '\CurrentVersion\Image File Execution Options\'
    selection2:
        CommandLine|contains:
            - 'sethc.exe'
            - 'utilman.exe'
            - 'osk.exe'
            - 'magnify.exe'
            - 'narrator.exe'
            - 'displayswitch.exe'
            - 'atbroker.exe'
            - 'HelpPane.exe'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
