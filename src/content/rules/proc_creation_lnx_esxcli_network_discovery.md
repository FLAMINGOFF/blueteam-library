---
title: ESXi Network Configuration Discovery Via ESXCLI
summary: Detects execution of the "esxcli" command with the "network" flag in order to retrieve information about the network configuration.
sigma_id: 33e814e0-1f00-4e43-9c34-31fb7ae2b174
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
  - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_network.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_esxcli_network_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: ESXi Network Configuration Discovery Via ESXCLI
id: 33e814e0-1f00-4e43-9c34-31fb7ae2b174
status: test
description: Detects execution of the "esxcli" command with the "network" flag in order to retrieve information about the network configuration.
references:
    - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_network.html
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
        CommandLine|contains: 'network'
    selection_cli:
        CommandLine|contains:
            - ' get'
            - ' list'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
# Note: level can be reduced to low in some envs
level: medium
```
