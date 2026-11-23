---
title: Run PowerShell Script from Redirected Input Stream
summary: Detects PowerShell script execution via input stream redirect
sigma_id: c83bf4b5-cdf0-437c-90fa-43d734f7c476
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Moriarty Meng (idea), Anton Kutepov (rule), oscd.community
date: '2020-10-17'
modified: '2021-11-27'
falsepositives:
  - Unknown
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OSBinaries/Powershell.yml
  - https://twitter.com/Moriarty_Meng/status/984380793383370752
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_run_script_from_input_stream.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Run PowerShell Script from Redirected Input Stream
id: c83bf4b5-cdf0-437c-90fa-43d734f7c476
status: test
description: Detects PowerShell script execution via input stream redirect
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OSBinaries/Powershell.yml
    - https://twitter.com/Moriarty_Meng/status/984380793383370752
author: Moriarty Meng (idea), Anton Kutepov (rule), oscd.community
date: 2020-10-17
modified: 2021-11-27
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|re: '\s-\s*<'
    condition: selection
falsepositives:
    - Unknown
level: high
```
