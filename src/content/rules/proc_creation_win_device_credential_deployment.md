---
title: DeviceCredentialDeployment Execution
summary: Detects the execution of DeviceCredentialDeployment to hide a process from view.
sigma_id: b8b1b304-a60f-4999-9a6e-c547bde03ffd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-19'
falsepositives:
  - Unlikely
references:
  - https://github.com/LOLBAS-Project/LOLBAS/pull/147
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_device_credential_deployment.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DeviceCredentialDeployment Execution
id: b8b1b304-a60f-4999-9a6e-c547bde03ffd
status: test
description: |
    Detects the execution of DeviceCredentialDeployment to hide a process from view.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/147
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DeviceCredentialDeployment.exe'
    condition: selection
falsepositives:
    - Unlikely
level: medium
```
