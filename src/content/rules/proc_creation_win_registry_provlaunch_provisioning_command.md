---
title: Potential Provisioning Registry Key Abuse For Binary Proxy Execution
summary: Detects potential abuse of the provisioning registry key for indirect command execution through "Provlaunch.exe".
sigma_id: 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: '2023-08-08'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
  - https://twitter.com/0gtweet/status/1674399582162153472
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_registry_provlaunch_provisioning_command.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Provisioning Registry Key Abuse For Binary Proxy Execution
id: 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25
related:
    - id: 7f5d1c9a-3e83-48df-95a7-2b98aae6c13c # CLI Generic
      type: similar
    - id: f9999590-1f94-4a34-a91e-951e47bedefd # CLI Abuse
      type: similar
    - id: 7021255e-5db3-4946-a8b9-0ba7a4644a69 # Registry
      type: similar
status: test
description: Detects potential abuse of the provisioning registry key for indirect command execution through "Provlaunch.exe".
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
    - https://twitter.com/0gtweet/status/1674399582162153472
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: 2023-08-08
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'SOFTWARE\Microsoft\Provisioning\Commands\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
