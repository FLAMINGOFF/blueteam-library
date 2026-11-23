---
title: Windows Shell/Scripting Processes Spawning Suspicious Programs
summary: Detects suspicious child processes of a Windows shell and scripting processes such as wscript, rundll32, powershell, mshta...etc.
sigma_id: 3a6586ad-127a-4d3b-a677-1e6eacdf8fde
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1059.005
  - T1059.001
  - T1218
author: Florian Roth (Nextron Systems), Tim Shelton
date: '2018-04-06'
modified: '2023-05-23'
falsepositives:
  - Administrative scripts
  - Microsoft SCCM
references:
  - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_shell_spawn_susp_program.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Shell/Scripting Processes Spawning Suspicious Programs
id: 3a6586ad-127a-4d3b-a677-1e6eacdf8fde
status: test
description: Detects suspicious child processes of a Windows shell and scripting processes such as wscript, rundll32, powershell, mshta...etc.
references:
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
author: Florian Roth (Nextron Systems), Tim Shelton
date: 2018-04-06
modified: 2023-05-23
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.005
    - attack.t1059.001
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            # - '\cmd.exe'  # too many false positives
            - '\rundll32.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\wmiprvse.exe'
            - '\regsvr32.exe'
        Image|endswith:
            - '\schtasks.exe'
            - '\nslookup.exe'
            - '\certutil.exe'
            - '\bitsadmin.exe'
            - '\mshta.exe'
    filter_ccmcache:
        CurrentDirectory|contains: '\ccmcache\'
    filter_amazon:
        ParentCommandLine|contains:
            # FP - Amazon Workspaces
            - '\Program Files\Amazon\WorkSpacesConfig\Scripts\setup-scheduledtask.ps1'
            - '\Program Files\Amazon\WorkSpacesConfig\Scripts\set-selfhealing.ps1'
            - '\Program Files\Amazon\WorkSpacesConfig\Scripts\check-workspacehealth.ps1'
            - '\nessus_' # Tenable/Nessus VA Scanner
    filter_nessus:
        CommandLine|contains: '\nessus_' # Tenable/Nessus VA Scanner
    filter_sccm_install:
        ParentImage|endswith: '\mshta.exe'
        Image|endswith: '\mshta.exe'
        ParentCommandLine|contains|all:
            - 'C:\MEM_Configmgr_'
            - '\splash.hta'
            - '{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}'
        CommandLine|contains|all:
            - 'C:\MEM_Configmgr_'
            - '\SMSSETUP\BIN\'
            - '\autorun.hta'
            - '{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}'
    condition: selection and not 1 of filter_*
falsepositives:
    - Administrative scripts
    - Microsoft SCCM
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_susp_shell_spawn_susp_program/info.yml
```
