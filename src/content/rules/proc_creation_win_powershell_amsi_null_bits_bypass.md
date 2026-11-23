---
title: Potential AMSI Bypass Using NULL Bits
summary: Detects usage of special strings/null bits in order to potentially bypass AMSI functionalities
sigma_id: 92a974db-ab84-457f-9ec0-55db83d7a825
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-04'
modified: '2023-05-09'
falsepositives:
  - Unknown
references:
  - https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#amsi-bypass-using-null-bits-satoshi
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_amsi_null_bits_bypass.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential AMSI Bypass Using NULL Bits
id: 92a974db-ab84-457f-9ec0-55db83d7a825
related:
    - id: fa2559c8-1197-471d-9cdd-05a0273d4522
      type: similar
status: test
description: Detects usage of special strings/null bits in order to potentially bypass AMSI functionalities
references:
    - https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#amsi-bypass-using-null-bits-satoshi
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-04
modified: 2023-05-09
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - "if(0){{{0}}}' -f $(0 -as [char]) +"
            - "#<NULL>"
    condition: selection
falsepositives:
    - Unknown
level: medium
```
