---
title: Suspicious X509Enrollment - Process Creation
summary: Detect use of X509Enrollment
sigma_id: 114de787-4eb2-48cc-abdb-c0b449f93ea4
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1553.004
author: frack113
date: '2022-12-23'
falsepositives:
  - Legitimate administrative script
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=42
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=41
  - https://learn.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.cx509enrollmentwebclassfactoryclass?view=hpc-sdk-5.1.6115
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_x509enrollment.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious X509Enrollment - Process Creation
id: 114de787-4eb2-48cc-abdb-c0b449f93ea4
related:
    - id: 504d63cb-0dba-4d02-8531-e72981aace2c
      type: similar
status: test
description: Detect use of X509Enrollment
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=42
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=41
    - https://learn.microsoft.com/en-us/dotnet/api/microsoft.hpc.scheduler.store.cx509enrollmentwebclassfactoryclass?view=hpc-sdk-5.1.6115
author: frack113
date: 2022-12-23
tags:
    - attack.defense-impairment
    - attack.t1553.004
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'X509Enrollment.CBinaryConverter'
            - '884e2002-217d-11da-b2a4-000e7bbb2b09'
    condition: selection
falsepositives:
    - Legitimate administrative script
level: medium
```
