---
title: Windows Credential Manager Access via VaultCmd
summary: List credentials currently stored in Windows Credential Manager via the native Windows utility vaultcmd.exe
sigma_id: 58f50261-c53b-4c88-bd12-1d71f12eda4c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1555.004
author: frack113
date: '2022-04-08'
modified: '2022-05-13'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555.004/T1555.004.md#atomic-test-1---access-saved-credentials-via-vaultcmd
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vaultcmd_list_creds.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Credential Manager Access via VaultCmd
id: 58f50261-c53b-4c88-bd12-1d71f12eda4c
status: test
description: List credentials currently stored in Windows Credential Manager via the native Windows utility vaultcmd.exe
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555.004/T1555.004.md#atomic-test-1---access-saved-credentials-via-vaultcmd
author: frack113
date: 2022-04-08
modified: 2022-05-13
tags:
    - attack.credential-access
    - attack.t1555.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\VaultCmd.exe'
        - OriginalFileName: 'VAULTCMD.EXE'
    selection_cli:
        CommandLine|contains: '/listcreds:'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
