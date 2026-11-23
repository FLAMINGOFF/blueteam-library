---
title: Disabling Security Tools
summary: Detects disabling security tools
sigma_id: e3a8a052-111f-4606-9aee-f28ebeb76776
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0112
techniques:
  - T1686
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: '2020-06-17'
modified: '2022-10-09'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_security_tools_disabling.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Disabling Security Tools
id: e3a8a052-111f-4606-9aee-f28ebeb76776
status: test
description: Detects disabling security tools
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.004/T1562.004.md
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020-06-17
modified: 2022-10-09
tags:
    - attack.defense-impairment
    - attack.t1686
logsource:
    category: process_creation
    product: linux
detection:
    selection_iptables_1:
        Image|endswith: '/service'
        CommandLine|contains|all:
            - 'iptables'
            - 'stop'
    selection_iptables_2:
        Image|endswith: '/service'
        CommandLine|contains|all:
            - 'ip6tables'
            - 'stop'
    selection_iptables_3:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
            - 'iptables'
            - 'stop'
    selection_iptables_4:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
            - 'ip6tables'
            - 'stop'
    selection_firewall_1:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'firewalld'
            - 'stop'
    selection_firewall_2:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'firewalld'
            - 'disable'
    selection_carbonblack_1:
        Image|endswith: '/service'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'stop'
    selection_carbonblack_2:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'off'
    selection_carbonblack_3:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'stop'
    selection_carbonblack_4:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'cbdaemon'
            - 'disable'
    selection_selinux:
        Image|endswith: '/setenforce'
        CommandLine|contains: '0'
    selection_crowdstrike_1:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'stop'
            - 'falcon-sensor'
    selection_crowdstrike_2:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
            - 'disable'
            - 'falcon-sensor'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: medium
```
