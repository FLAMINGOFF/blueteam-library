---
title: Suspicious Modification Of Scheduled Tasks
summary: |-
  Detects when an attacker tries to modify an already existing scheduled tasks to run from a suspicious location
  Attackers can create a simple looking task in order to avoid detection on creation as it's often the most focused on
  Instead they modify the task after creation to include their malicious payload
sigma_id: 1c0e41cd-21bb-4433-9acc-4a2cd6367b9b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1053.005
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-28'
modified: '2022-11-18'
falsepositives:
  - Unknown
references:
  - Internal Research
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_change.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Modification Of Scheduled Tasks
id: 1c0e41cd-21bb-4433-9acc-4a2cd6367b9b
related:
    - id: 614cf376-6651-47c4-9dcc-6b9527f749f4 # Security-Audting Eventlog
      type: similar
status: test
description: |
    Detects when an attacker tries to modify an already existing scheduled tasks to run from a suspicious location
    Attackers can create a simple looking task in order to avoid detection on creation as it's often the most focused on
    Instead they modify the task after creation to include their malicious payload
references:
    - Internal Research
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-28
modified: 2022-11-18
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_schtasks:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - ' /Change '
            - ' /TN '
    selection_susp_locations:
        CommandLine|contains:
            - '\AppData\Local\Temp'
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\WINDOWS\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Temporary Internet'
            - 'C:\ProgramData\'
            - 'C:\Perflogs\'
            - '%ProgramData%'
            - '%appdata%'
            - '%comspec%'
            - '%localappdata%'
    selection_susp_images:
        CommandLine|contains:
            - 'regsvr32'
            - 'rundll32'
            - 'cmd /c '
            - 'cmd /k '
            - 'cmd /r '
            - 'cmd.exe /c '
            - 'cmd.exe /k '
            - 'cmd.exe /r '
            - 'powershell'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'certutil'
            - 'bitsadmin'
            - 'bash.exe'
            - 'bash '
            - 'scrcons'
            - 'wmic '
            - 'wmic.exe'
            - 'forfiles'
            - 'scriptrunner'
            - 'hh.exe'
            - 'hh '
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
