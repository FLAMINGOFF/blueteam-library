---
title: Use of OpenConsole
summary: Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting
sigma_id: 814c95cc-8192-4378-a70a-f1aafd877af1
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-16'
falsepositives:
  - Legitimate use by an administrator
references:
  - https://twitter.com/nas_bench/status/1537563834478645252
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_openconsole.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of OpenConsole
id: 814c95cc-8192-4378-a70a-f1aafd877af1
status: test
description: Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting
references:
    - https://twitter.com/nas_bench/status/1537563834478645252
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-16
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'OpenConsole.exe'
        - Image|endswith: '\OpenConsole.exe'
    filter:
        Image|startswith: 'C:\Program Files\WindowsApps\Microsoft.WindowsTerminal' # We exclude the default path for WindowsTerminal
    condition: selection and not filter
falsepositives:
    - Legitimate use by an administrator
level: medium
```
