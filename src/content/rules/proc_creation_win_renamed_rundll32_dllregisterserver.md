---
title: Potential Renamed Rundll32 Execution
summary: Detects when 'DllRegisterServer' is called in the commandline and the image is not rundll32. This could mean that the 'rundll32' utility has been renamed in order to avoid detection
sigma_id: 2569ed8c-1147-498a-9b8c-2ad3656b10ed
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-22'
modified: '2023-02-03'
falsepositives:
  - Unlikely
references:
  - https://twitter.com/swisscom_csirt/status/1331634525722521602?s=20
  - https://app.any.run/tasks/f74c5157-8508-4ac6-9805-d63fe7b0d399/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Renamed Rundll32 Execution
id: 2569ed8c-1147-498a-9b8c-2ad3656b10ed
related:
    - id: 0ba1da6d-b6ce-4366-828c-18826c9de23e
      type: derived
status: test
description: Detects when 'DllRegisterServer' is called in the commandline and the image is not rundll32. This could mean that the 'rundll32' utility has been renamed in order to avoid detection
references:
    - https://twitter.com/swisscom_csirt/status/1331634525722521602?s=20
    - https://app.any.run/tasks/f74c5157-8508-4ac6-9805-d63fe7b0d399/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-22
modified: 2023-02-03
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'DllRegisterServer'
    filter:
        Image|endswith: '\rundll32.exe'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
```
