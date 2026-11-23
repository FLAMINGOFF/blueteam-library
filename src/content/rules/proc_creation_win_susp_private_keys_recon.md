---
title: Private Keys Reconnaissance Via CommandLine Tools
summary: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
sigma_id: 213d6a77-3d55-4ce8-ba74-fcfef741974e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1552.004
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: '2021-07-20'
modified: '2023-03-06'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.004/T1552.004.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_private_keys_recon.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Private Keys Reconnaissance Via CommandLine Tools
id: 213d6a77-3d55-4ce8-ba74-fcfef741974e
status: test
description: Adversaries may search for private key certificate files on compromised systems for insecurely stored credential
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.004/T1552.004.md
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2021-07-20
modified: 2023-03-06
tags:
    - attack.credential-access
    - attack.t1552.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'Cmd.Exe'
    selection_cmd_cli:
        CommandLine|contains: 'dir '
    selection_pwsh_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_pwsh_cli:
        CommandLine|contains: 'Get-ChildItem '
    selection_findstr:
        - Image|endswith: '\findstr.exe'
        - OriginalFileName: 'FINDSTR.EXE'
    selection_ext:
        CommandLine|contains:
            - '.key'
            - '.pgp'
            - '.gpg'
            - '.ppk'
            - '.p12'
            - '.pem'
            - '.pfx'
            - '.cer'
            - '.p7b'
            - '.asc'
    condition: selection_ext and (all of selection_cmd_* or all of selection_pwsh_* or selection_findstr)
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_susp_private_keys_recon/info.yml
```
