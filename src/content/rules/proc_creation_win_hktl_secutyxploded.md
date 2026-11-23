---
title: HackTool - SecurityXploded Execution
summary: Detects the execution of SecurityXploded Tools
sigma_id: 7679d464-4f74-45e2-9e01-ac66c5eb041a
status: stable
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1555
author: Florian Roth (Nextron Systems)
date: '2018-12-19'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://securityxploded.com/
  - https://web.archive.org/web/20200601000524/https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_secutyxploded.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SecurityXploded Execution
id: 7679d464-4f74-45e2-9e01-ac66c5eb041a
status: stable
description: Detects the execution of SecurityXploded Tools
references:
    - https://securityxploded.com/
    - https://web.archive.org/web/20200601000524/https://cyberx-labs.com/blog/gangnam-industrial-style-apt-campaign-targets-korean-industrial-companies/
author: Florian Roth (Nextron Systems)
date: 2018-12-19
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1555
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Company: SecurityXploded
        - Image|endswith: 'PasswordDump.exe'
        - OriginalFileName|endswith: 'PasswordDump.exe'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
