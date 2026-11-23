---
title: Launch-VsDevShell.PS1 Proxy Execution
summary: Detects the use of the 'Launch-VsDevShell.ps1' Microsoft signed script to execute commands.
sigma_id: 45d3a03d-f441-458c-8883-df101a3bb146
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1216.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-19'
falsepositives:
  - Legitimate usage of the script by a developer
references:
  - https://twitter.com/nas_bench/status/1535981653239255040
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_launch_vsdevshell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Launch-VsDevShell.PS1 Proxy Execution
id: 45d3a03d-f441-458c-8883-df101a3bb146
status: test
description: Detects the use of the 'Launch-VsDevShell.ps1' Microsoft signed script to execute commands.
references:
    - https://twitter.com/nas_bench/status/1535981653239255040
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.stealth
    - attack.t1216.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_script:
        CommandLine|contains: 'Launch-VsDevShell.ps1'
    selection_flags:
        CommandLine|contains:
            - 'VsWherePath '
            - 'VsInstallationPath '
    condition: all of selection_*
falsepositives:
    - Legitimate usage of the script by a developer
level: medium
```
