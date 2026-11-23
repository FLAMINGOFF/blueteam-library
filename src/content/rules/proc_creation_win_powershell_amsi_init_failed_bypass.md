---
title: Potential AMSI Bypass Via .NET Reflection
summary: Detects Request to "amsiInitFailed" that can be used to disable AMSI Scanning
sigma_id: 30edb182-aa75-42c0-b0a9-e998bb29067c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: Markus Neis, @Kostastsale
date: '2018-08-17'
modified: '2023-02-03'
falsepositives:
  - Unlikely
references:
  - https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/
  - https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_amsi_init_failed_bypass.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential AMSI Bypass Via .NET Reflection
id: 30edb182-aa75-42c0-b0a9-e998bb29067c
related:
    - id: 4f927692-68b5-4267-871b-073c45f4f6fe
      type: obsolete
status: test
description: Detects Request to "amsiInitFailed" that can be used to disable AMSI Scanning
references:
    - https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/
    - https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
author: Markus Neis, @Kostastsale
date: 2018-08-17
modified: 2023-02-03
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains|all:
              - 'System.Management.Automation.AmsiUtils'
              - 'amsiInitFailed'
        - CommandLine|contains|all:
              - '[Ref].Assembly.GetType'
              - 'SetValue($null,$true)'
              - 'NonPublic,Static'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
