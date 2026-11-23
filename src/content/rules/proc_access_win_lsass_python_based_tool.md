---
title: Credential Dumping Activity By Python Based Tool
summary: Detects LSASS process access for potential credential dumping by a Python-like tool such as LaZagne or Pypykatz.
sigma_id: f8be3e82-46a3-4e4e-ada5-8e538ae8b9c9
status: stable
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0006
techniques:
  - T1003.001
author: Bhabesh Raj, Jonhnathan Ribeiro
date: '2023-11-27'
modified: '2023-11-29'
falsepositives:
  - Unknown
references:
  - https://twitter.com/bh4b3sh/status/1303674603819081728
  - https://github.com/skelsec/pypykatz
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_lsass_python_based_tool.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Credential Dumping Activity By Python Based Tool
id: f8be3e82-46a3-4e4e-ada5-8e538ae8b9c9
related:
    - id: 4b9a8556-99c4-470b-a40c-9c8d02c77ed0
      type: obsolete
    - id: 7186e989-4ed7-4f4e-a656-4674b9e3e48b
      type: obsolete
status: stable
description: Detects LSASS process access for potential credential dumping by a Python-like tool such as LaZagne or Pypykatz.
references:
    - https://twitter.com/bh4b3sh/status/1303674603819081728
    - https://github.com/skelsec/pypykatz
author: Bhabesh Raj, Jonhnathan Ribeiro
date: 2023-11-27
modified: 2023-11-29
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.s0349
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        CallTrace|contains|all:
            - '_ctypes.pyd+'
            - ':\Windows\System32\KERNELBASE.dll+'
            - ':\Windows\SYSTEM32\ntdll.dll+'
        CallTrace|contains:
            - 'python27.dll+'
            - 'python3*.dll+'
        GrantedAccess: '0x1FFFFF'
    condition: selection
falsepositives:
    - Unknown
level: high
```
