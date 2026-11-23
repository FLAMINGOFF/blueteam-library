---
title: Delete Important Scheduled Task
summary: Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities
sigma_id: dbc1f800-0fe0-4bc0-9c66-292c2abe3f78
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1489
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-09'
modified: '2026-03-11'
falsepositives:
  - Unlikely
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_delete.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Delete Important Scheduled Task
id: dbc1f800-0fe0-4bc0-9c66-292c2abe3f78
related:
    - id: 9e3cb244-bdb8-4632-8c90-6079c8f4f16d # TaskScheduler EventLog
      type: similar
    - id: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad # Security-Audting Eventlog
      type: similar
status: test
description: Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
modified: 2026-03-11
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_cli_delete:
        CommandLine|contains|windash: '/delete'
    selection_cli_task:
        CommandLine|contains:
            # Add more important tasks
            - '\Windows\BitLocker'
            - '\Windows\ExploitGuard'
            - '\Windows\SystemRestore\SR'
            - '\Windows\UpdateOrchestrator\'
            - '\Windows\Windows Defender\'
            - '\Windows\WindowsBackup\'
            - '\Windows\WindowsUpdate\'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_schtasks_delete/info.yml
```
