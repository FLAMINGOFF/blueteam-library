---
title: Vulnerable Driver Blocklist Registry Tampering Via CommandLine
summary: |-
  Detects tampering of the Vulnerable Driver Blocklist registry via command line tools such as PowerShell or REG.EXE.
  The Vulnerable Driver Blocklist is a security feature that helps prevent the loading of known vulnerable drivers.
  Disabling this feature may indicate an attempt to bypass security controls, often targeted by threat actors
  to facilitate the installation of malicious or vulnerable drivers, particularly in scenarios involving Endpoint Detection and Response
sigma_id: 22154f0e-5132-4a54-aa78-cc62f6def531
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2026-01-26'
falsepositives:
  - It is very unlikely for legitimate activities to disable the Vulnerable Driver Blocklist via command line tools; thus it is recommended to investigate promptly.
references:
  - https://www.sophos.com/en-us/blog/sharpening-the-knife-gold-blades-strategic-evolution
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vulnerable_driver_blocklist_registry_tampering.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Vulnerable Driver Blocklist Registry Tampering Via CommandLine
id: 22154f0e-5132-4a54-aa78-cc62f6def531
related:
    - id: d526c60a-e236-4011-b165-831ffa52ab70
      type: similar
status: experimental
description: |
    Detects tampering of the Vulnerable Driver Blocklist registry via command line tools such as PowerShell or REG.EXE.
    The Vulnerable Driver Blocklist is a security feature that helps prevent the loading of known vulnerable drivers.
    Disabling this feature may indicate an attempt to bypass security controls, often targeted by threat actors
    to facilitate the installation of malicious or vulnerable drivers, particularly in scenarios involving Endpoint Detection and Response
references:
    - https://www.sophos.com/en-us/blog/sharpening-the-knife-gold-blades-strategic-evolution
    - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-01-26
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\reg.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
              - 'reg.exe'
    selection_cli_1:
        CommandLine|contains:
            - 'add '
            - 'New-ItemProperty '
            - 'Set-ItemProperty '
            - 'si '  # SetItem Alias
    selection_cli_2:
        CommandLine|contains|all:
            - '\Control\CI\Config'
            - 'VulnerableDriverBlocklistEnable'
    condition: all of selection_*
falsepositives:
    - It is very unlikely for legitimate activities to disable the Vulnerable Driver Blocklist via command line tools; thus it is recommended to investigate promptly.
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_vulnerable_driver_blocklist_registry_tampering/info.yml
```
