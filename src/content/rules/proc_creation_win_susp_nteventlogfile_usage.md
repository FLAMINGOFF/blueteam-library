---
title: Potentially Suspicious Call To Win32_NTEventlogFile Class
summary: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
sigma_id: caf201a9-c2ce-4a26-9c3a-2b9525413711
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-07-13'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394225(v=vs.85)
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_nteventlogfile_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Call To Win32_NTEventlogFile Class
id: caf201a9-c2ce-4a26-9c3a-2b9525413711
related:
    - id: e2812b49-bae0-4b21-b366-7c142eafcde2
      type: similar
status: test
description: Detects usage of the WMI class "Win32_NTEventlogFile" in a potentially suspicious way (delete, backup, change permissions, etc.) from a PowerShell script
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa394225(v=vs.85)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-07-13
tags:
    - attack.defense-impairment
logsource:
    category: process_creation
    product: windows
detection:
    selection_class:
        CommandLine|contains: 'Win32_NTEventlogFile'
    selection_function:
        CommandLine|contains:
            - '.BackupEventlog('
            - '.ChangeSecurityPermissions('
            - '.ChangeSecurityPermissionsEx('
            - '.ClearEventLog('
            - '.Delete('
            - '.DeleteEx('
            - '.Rename('
            - '.TakeOwnerShip('
            - '.TakeOwnerShipEx('
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
