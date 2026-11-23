---
title: Suspicious Redirection to Local Admin Share
summary: Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers
sigma_id: ab9e3b40-0c85-4ba1-aede-455d226fd124
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0010
techniques:
  - T1048
author: Florian Roth (Nextron Systems)
date: '2022-01-16'
modified: '2023-12-28'
falsepositives:
  - Unknown
references:
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_redirect_local_admin_share.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Redirection to Local Admin Share
id: ab9e3b40-0c85-4ba1-aede-455d226fd124
status: test
description: Detects a suspicious output redirection to the local admins share, this technique is often found in malicious scripts or hacktool stagers
references:
    - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
    - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
author: Florian Roth (Nextron Systems)
date: 2022-01-16
modified: 2023-12-28
tags:
    - attack.exfiltration
    - attack.t1048
logsource:
    category: process_creation
    product: windows
detection:
    selection_redirect:
        CommandLine|contains: '>'
    selection_share:
        CommandLine|contains:
            - '\\\\127.0.0.1\\admin$\\'
            - '\\\\localhost\\admin$\\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_susp_redirect_local_admin_share/info.yml
```
