---
title: Firewall Rule Update Via Netsh.EXE
summary: Detects execution of netsh with the "advfirewall" and the "set" option in order to set new values for properties of a existing rule
sigma_id: a70dcb37-3bee-453a-99df-d0c683151be6
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: X__Junior (Nextron Systems)
date: '2023-07-18'
falsepositives:
  - Legitimate administration activity
  - Software installations and removal
references:
  - https://ss64.com/nt/netsh.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_netsh_fw_set_rule.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Firewall Rule Update Via Netsh.EXE
id: a70dcb37-3bee-453a-99df-d0c683151be6
status: test
description: Detects execution of netsh with the "advfirewall" and the "set" option in order to set new values for properties of a existing rule
references:
    - https://ss64.com/nt/netsh.html
author: X__Junior (Nextron Systems)
date: 2023-07-18
tags:
    - attack.defense-impairment
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            # Example 1: netsh advfirewall firewall set rule "group=\"Network Discovery\" " new enable=Yes"
            # Example 2: netsh advfirewall firewall set rule "group=\"File and Printer Sharing\" " new enable=Yes"
            - ' firewall '
            - ' set '
    condition: all of selection_*
falsepositives:
    - Legitimate administration activity
    - Software installations and removal
level: medium
```
