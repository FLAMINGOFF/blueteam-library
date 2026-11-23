---
title: Suspicious Regsvr32 Execution From Remote Share
summary: Detects REGSVR32.exe to execute DLL hosted on remote shares
sigma_id: 88a87a10-384b-4ad7-8871-2f9bf9259ce5
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.010
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-31'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regsvr32_remote_share.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Regsvr32 Execution From Remote Share
id: 88a87a10-384b-4ad7-8871-2f9bf9259ce5
status: test
description: Detects REGSVR32.exe to execute DLL hosted on remote shares
references:
    - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-31
tags:
    - attack.stealth
    - attack.t1218.010
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regsvr32.exe'
        - OriginalFileName: '\REGSVR32.EXE'
    selection_cli:
        CommandLine|contains: ' \\\\'
    condition: all of selection_*
falsepositives:
    - Unknown
# Decrease to medium if this is something common in your org
level: high
```
