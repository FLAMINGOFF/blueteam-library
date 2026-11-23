---
title: PowerShell Base64 Encoded IEX Cmdlet
summary: Detects usage of a base64 encoded "IEX" cmdlet in a process command line
sigma_id: 88f680b8-070e-402c-ae11-d2914f2257f1
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: Florian Roth (Nextron Systems)
date: '2019-08-23'
modified: '2023-04-06'
falsepositives:
  - Unknown
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PowerShell Base64 Encoded IEX Cmdlet
id: 88f680b8-070e-402c-ae11-d2914f2257f1
status: test
description: Detects usage of a base64 encoded "IEX" cmdlet in a process command line
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2019-08-23
modified: 2023-04-06
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|base64offset|contains:
              - 'IEX (['
              - 'iex (['
              - 'iex (New'
              - 'IEX (New'
              - 'IEX(['
              - 'iex(['
              - 'iex(New'
              - 'IEX(New'
              - "IEX(('"
              - "iex(('"
        # UTF16 LE
        - CommandLine|contains:
              - 'SQBFAFgAIAAoAFsA'
              - 'kARQBYACAAKABbA'
              - 'JAEUAWAAgACgAWw'
              - 'aQBlAHgAIAAoAFsA'
              - 'kAZQB4ACAAKABbA'
              - 'pAGUAeAAgACgAWw'
              - 'aQBlAHgAIAAoAE4AZQB3A'
              - 'kAZQB4ACAAKABOAGUAdw'
              - 'pAGUAeAAgACgATgBlAHcA'
              - 'SQBFAFgAIAAoAE4AZQB3A'
              - 'kARQBYACAAKABOAGUAdw'
              - 'JAEUAWAAgACgATgBlAHcA'
    condition: selection
falsepositives:
    - Unknown
level: high
```
