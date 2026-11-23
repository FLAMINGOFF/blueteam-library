---
title: Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths
summary: Detects the execution of the "wusa.exe" (Windows Update Standalone Installer) utility to extract ".cab" files using the "/extract" argument from potentially suspicious paths.
sigma_id: c74c0390-3e20-41fd-a69a-128f0275a5ea
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-05'
modified: '2023-11-28'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
  - https://www.echotrail.io/insights/search/wusa.exe/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wusa_cab_files_extraction_from_susp_paths.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths
id: c74c0390-3e20-41fd-a69a-128f0275a5ea
related:
    - id: 59b39960-5f9d-4a49-9cef-1e4d2c1d0cb9
      type: derived
status: test
description: |
    Detects the execution of the "wusa.exe" (Windows Update Standalone Installer) utility to extract ".cab" files using the "/extract" argument from potentially suspicious paths.
references:
    - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
    - https://www.echotrail.io/insights/search/wusa.exe/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-05
modified: 2023-11-28
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_root:
        Image|endswith: '\wusa.exe'
        CommandLine|contains: '/extract:'
    selection_paths:
        CommandLine|contains:
            - ':\PerfLogs\'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\Appdata\Local\Temp\'
            # - '\Desktop\'
            # - '\Downloads\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
