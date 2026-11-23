---
title: SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code
summary: Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs
sigma_id: 36475a7d-0f6d-4dce-9b01-6aeb473bbaf1
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
  - T1216
author: frack113
date: '2021-07-16'
modified: '2022-06-22'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1216/T1216.md
  - https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_vbs_execute_psh.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code
id: 36475a7d-0f6d-4dce-9b01-6aeb473bbaf1
status: test
description: Executes arbitrary PowerShell code using SyncAppvPublishingServer.vbs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1216/T1216.md
    - https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/
author: frack113
date: 2021-07-16
modified: 2022-06-22
tags:
    - attack.stealth
    - attack.t1218
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\SyncAppvPublishingServer.vbs'
            - ';'  # at a minimum, a semi-colon is required
    condition: selection
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_lolbin_syncappvpublishingserver_vbs_execute_psh/info.yml
```
