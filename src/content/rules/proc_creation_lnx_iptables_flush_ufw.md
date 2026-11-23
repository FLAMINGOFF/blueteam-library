---
title: Flush Iptables Ufw Chain
summary: Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic
sigma_id: 3be619f4-d9ec-4ea8-a173-18fdd01996ab
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1686
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: '2023-01-18'
falsepositives:
  - Network administrators
references:
  - https://blogs.blackberry.com/
  - https://www.cyberciti.biz/tips/linux-iptables-how-to-flush-all-rules.html
  - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_iptables_flush_ufw.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Flush Iptables Ufw Chain
id: 3be619f4-d9ec-4ea8-a173-18fdd01996ab
status: test
description: Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic
references:
    - https://blogs.blackberry.com/
    - https://www.cyberciti.biz/tips/linux-iptables-how-to-flush-all-rules.html
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-18
tags:
    - attack.defense-impairment
    - attack.t1686
logsource:
    product: linux
    category: process_creation
detection:
    selection_img:
        Image|endswith:
            - '/iptables'
            - '/xtables-legacy-multi'
            - '/iptables-legacy-multi'
            - '/ip6tables'
            - '/ip6tables-legacy-multi'
    selection_params:
        CommandLine|contains:
            - '-F'
            - '-Z'
            - '-X'
    selection_ufw:
        CommandLine|contains:
            - 'ufw-logging-deny'
            - 'ufw-logging-allow'
            - 'ufw6-logging-deny'
            - 'ufw6-logging-allow'
            # - 'ufw-reject-output'
            # - 'ufw-track-inputt'
    condition: all of selection_*
falsepositives:
    - Network administrators
level: medium
```
