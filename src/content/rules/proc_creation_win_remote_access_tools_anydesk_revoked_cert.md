---
title: Remote Access Tool - AnyDesk Execution With Known Revoked Signing Certificate
summary: |-
  Detects the execution of an AnyDesk binary with a version prior to 8.0.8.
  Prior to version 8.0.8, the Anydesk application used a signing certificate that got compromised by threat actors.
  Use this rule to detect instances of older versions of Anydesk using the compromised certificate
  This is recommended in order to avoid attackers leveraging the certificate and signing their binaries to bypass detections.
sigma_id: 41f407b5-3096-44ea-a74f-96d04fbc41be
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0001
techniques: []
author: Sai Prashanth Pulisetti, Nasreddine Bencherchali (Nextron Systems)
date: '2024-02-08'
falsepositives:
  - Unlikely
references:
  - https://www.bleepingcomputer.com/news/security/anydesk-says-hackers-breached-its-production-servers-reset-passwords/
  - https://anydesk.com/en/changelog/windows
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_revoked_cert.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - AnyDesk Execution With Known Revoked Signing Certificate
id: 41f407b5-3096-44ea-a74f-96d04fbc41be
status: test
description: |
    Detects the execution of an AnyDesk binary with a version prior to 8.0.8.
    Prior to version 8.0.8, the Anydesk application used a signing certificate that got compromised by threat actors.
    Use this rule to detect instances of older versions of Anydesk using the compromised certificate
    This is recommended in order to avoid attackers leveraging the certificate and signing their binaries to bypass detections.
references:
    - https://www.bleepingcomputer.com/news/security/anydesk-says-hackers-breached-its-production-servers-reset-passwords/
    - https://anydesk.com/en/changelog/windows
author: Sai Prashanth Pulisetti, Nasreddine Bencherchali (Nextron Systems)
date: 2024-02-08
tags:
    - attack.execution
    - attack.initial-access
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\AnyDesk.exe'
        - Description: 'AnyDesk'
        - Product: 'AnyDesk'
        - Company: 'AnyDesk Software GmbH'
    selection_version:
        FileVersion|startswith:
            - '7.0.'
            - '7.1.'
            - '8.0.1'
            - '8.0.2'
            - '8.0.3'
            - '8.0.4'
            - '8.0.5'
            - '8.0.6'
            - '8.0.7'
    filter_main_uninstall:
        CommandLine|contains:
            - ' --remove'
            - ' --uninstall'
    condition: all of selection_* and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: medium
```
