---
title: Python Function Execution Security Warning Disabled In Excel
summary: |-
  Detects changes to the registry value "PythonFunctionWarnings" that would prevent any warnings or alerts from showing when Python functions are about to be executed.
  Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet.
sigma_id: 023c654f-8f16-44d9-bb2b-00ff36a62af9
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: '@Kostastsale'
date: '2023-08-22'
falsepositives:
  - Unknown
references:
  - https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_registry_office_disable_python_security_warnings.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Python Function Execution Security Warning Disabled In Excel
id: 023c654f-8f16-44d9-bb2b-00ff36a62af9
related:
    - id: 17e53739-a1fc-4a62-b1b9-87711c2d5e44
      type: similar
status: test
description: |
    Detects changes to the registry value "PythonFunctionWarnings" that would prevent any warnings or alerts from showing when Python functions are about to be executed.
    Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet.
references:
    - https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327
author: '@Kostastsale'
date: 2023-08-22
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\Microsoft\Office\'
            - '\Excel\Security'
            - 'PythonFunctionWarnings'
        CommandLine|contains: ' 0'
    condition: selection
falsepositives:
    - Unknown
level: high
```
