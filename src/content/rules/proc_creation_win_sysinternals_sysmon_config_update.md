---
title: Sysmon Configuration Update
summary: Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely
sigma_id: 87911521-7098-470b-a459-9a57fc80bdfd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-03-09'
modified: '2026-06-29'
falsepositives:
  - Legitimate administrators might use this command to update Sysmon configuration.
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_sysmon_config_update.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Sysmon Configuration Update
id: 87911521-7098-470b-a459-9a57fc80bdfd
status: test
description: Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-09
modified: 2026-06-29
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        - Image|endswith:
              - \Sysmon64.exe
              - \Sysmon64a.exe
              - \Sysmon.exe
        - Description: 'System activity monitor'
    selection_cli:
        CommandLine|contains|windash: '-c'
    condition: all of selection_*
falsepositives:
    - Legitimate administrators might use this command to update Sysmon configuration.
level: medium
```
