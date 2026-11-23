---
title: Triple Cross eBPF Rootkit Install Commands
summary: Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script
sigma_id: 22236d75-d5a0-4287-bf06-c93b1770860f
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0005
techniques:
  - T1014
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-05'
falsepositives:
  - Unlikely
references:
  - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_install.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Triple Cross eBPF Rootkit Install Commands
id: 22236d75-d5a0-4287-bf06-c93b1770860f
status: test
description: Detects default install commands of the Triple Cross eBPF rootkit based on the "deployer.sh" script
references:
    - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-05
tags:
    - attack.stealth
    - attack.t1014
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/sudo'
        CommandLine|contains|all:
            - ' tc '
            - ' enp0s3 '
        CommandLine|contains:
            - ' qdisc '
            - ' filter '
    condition: selection
falsepositives:
    - Unlikely
level: high
```
