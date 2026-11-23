---
title: Potential DLL File Download Via PowerShell Invoke-WebRequest
summary: Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest or Invoke-RestMethod cmdlets.
sigma_id: 0f0450f3-8b47-441e-a31b-15a91dc243e2
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
  - TA0002
techniques:
  - T1059.001
  - T1105
author: Florian Roth (Nextron Systems), Hieu Tran
date: '2023-03-13'
modified: '2025-07-18'
falsepositives:
  - Unknown
references:
  - https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_download_dll.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential DLL File Download Via PowerShell Invoke-WebRequest
id: 0f0450f3-8b47-441e-a31b-15a91dc243e2
status: test
description: Detects potential DLL files being downloaded using the PowerShell Invoke-WebRequest or Invoke-RestMethod cmdlets.
references:
    - https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution
author: Florian Roth (Nextron Systems), Hieu Tran
date: 2023-03-13
modified: 2025-07-18
tags:
    - attack.command-and-control
    - attack.execution
    - attack.t1059.001
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-RestMethod '
            - 'Invoke-WebRequest '
            - 'IRM '
            - 'IWR '
        CommandLine|contains|all:
            - 'http'
            - 'OutFile'
            - '.dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_powershell_download_dll/info.yml
```
