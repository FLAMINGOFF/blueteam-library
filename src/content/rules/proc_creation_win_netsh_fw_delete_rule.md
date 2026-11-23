---
title: Firewall Rule Deleted Via Netsh.EXE
summary: Detects the removal of a port or application rule in the Windows Firewall configuration using netsh
sigma_id: 1a5fefe6-734f-452e-a07d-fc1c35bce4b2
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1686.003
author: frack113
date: '2022-08-14'
modified: '2025-10-07'
falsepositives:
  - Legitimate administration activity
  - Software installations and removal
references:
  - https://app.any.run/tasks/8bbd5b4c-b82d-4e6d-a3ea-d454594a37cc/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_netsh_fw_delete_rule.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Firewall Rule Deleted Via Netsh.EXE
id: 1a5fefe6-734f-452e-a07d-fc1c35bce4b2
status: test
description: Detects the removal of a port or application rule in the Windows Firewall configuration using netsh
references:
    - https://app.any.run/tasks/8bbd5b4c-b82d-4e6d-a3ea-d454594a37cc/
author: frack113
date: 2022-08-14
modified: 2025-10-07
tags:
    - attack.defense-impairment
    - attack.t1686.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'firewall'
            - 'delete '
    filter_optional_dropbox:
        ParentImage|endswith: '\Dropbox.exe'
        CommandLine|contains: 'name=Dropbox'
    filter_optional_avast:
        ParentImage|endswith: '\instup.exe'
        CommandLine|contains: 'advfirewall firewall delete rule name="Avast Antivirus Admin Client"'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate administration activity
    - Software installations and removal
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_netsh_fw_delete_rule/info.yml
```
