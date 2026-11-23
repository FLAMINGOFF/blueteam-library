---
title: Copy From Or To Admin Share Or Sysvol Folder
summary: Detects a copy command or a copy utility execution to or from an Admin share or remote
sigma_id: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
  - TA0009
  - TA0010
techniques:
  - T1039
  - T1048
  - T1021.002
author: Florian Roth (Nextron Systems), oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Nasreddine Bencherchali
date: '2019-12-30'
modified: '2025-10-22'
falsepositives:
  - Administrative scripts
references:
  - https://twitter.com/SBousseaden/status/1211636381086339073
  - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
  - https://www.elastic.co/guide/en/security/current/remote-file-copy-to-a-hidden-share.html
  - https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Copy From Or To Admin Share Or Sysvol Folder
id: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
status: test
description: Detects a copy command or a copy utility execution to or from an Admin share or remote
references:
    - https://twitter.com/SBousseaden/status/1211636381086339073
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
    - https://www.elastic.co/guide/en/security/current/remote-file-copy-to-a-hidden-share.html
    - https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
author: Florian Roth (Nextron Systems), oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Nasreddine Bencherchali
date: 2019-12-30
modified: 2025-10-22
tags:
    - attack.lateral-movement
    - attack.collection
    - attack.exfiltration
    - attack.t1039
    - attack.t1048
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_target:
        CommandLine|contains:
            - '\\\\*\\*$' # example \\SVR_NAME\ADMIN$
            - '\Sysvol\'
    selection_other_tools:
        - Image|endswith:
              - '\robocopy.exe'
              - '\xcopy.exe'
        - OriginalFileName:
              - 'robocopy.exe'
              - 'XCOPY.EXE'
    selection_cmd_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cmd_cli:
        CommandLine|contains: 'copy'
    selection_pwsh_img:
        - Image|contains:
              - '\powershell_ise.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'powershell_ise.exe'
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_pwsh_cli:
        CommandLine|contains:
            - 'copy-item'
            - 'copy '
            - 'cpi '
            - ' cp '
            - 'move '
            - ' move-item'
            - ' mi '
            - ' mv '
    condition: selection_target and (selection_other_tools or all of selection_cmd_* or all of selection_pwsh_*)
falsepositives:
    - Administrative scripts
level: medium
```
