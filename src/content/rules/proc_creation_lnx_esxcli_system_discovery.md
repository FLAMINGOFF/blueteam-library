---
title: ESXi System Information Discovery Via ESXCLI
summary: Detects execution of the "esxcli" command with the "system" flag in order to retrieve information about the different component of the system. Such as accounts, modules, NTP, etc.
sigma_id: e80273e1-9faf-40bc-bd85-dbaff104c4e9
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
  - TA0002
techniques:
  - T1033
  - T1007
  - T1059.012
author: Cedric Maurugeon
date: '2023-09-04'
falsepositives:
  - Legitimate administration activities
references:
  - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
  - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_esxcli_system_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: ESXi System Information Discovery Via ESXCLI
id: e80273e1-9faf-40bc-bd85-dbaff104c4e9
status: test
description: Detects execution of the "esxcli" command with the "system" flag in order to retrieve information about the different component of the system. Such as accounts, modules, NTP, etc.
references:
    - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023-09-04
tags:
    - attack.discovery
    - attack.execution
    - attack.t1033
    - attack.t1007
    - attack.t1059.012
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'system'
    selection_cli:
        CommandLine|contains:
            - ' get'
            - ' list'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
level: medium
```
