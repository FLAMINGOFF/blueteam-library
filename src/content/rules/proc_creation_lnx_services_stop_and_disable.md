---
title: Disable Or Stop Services
summary: |-
  Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services on Linux systems.
  Attackers may stop or disable security tools and services to evade detection, maintain persistence, or disrupt system operations.
sigma_id: de25eeb8-3655-4643-ac3a-b662d3f26b6b
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0040
techniques:
  - T1685
  - T1489
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-15'
modified: '2025-03-18'
falsepositives:
  - Legitimate administration activities
  - Some false positives are to be expected. Apply additional filters as needed before pushing to production.
references:
  - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_services_stop_and_disable.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Disable Or Stop Services
id: de25eeb8-3655-4643-ac3a-b662d3f26b6b
status: test
description: |
    Detects the usage of utilities such as 'systemctl', 'service'...etc to stop or disable tools and services on Linux systems.
    Attackers may stop or disable security tools and services to evade detection, maintain persistence, or disrupt system operations.
references:
    - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
modified: 2025-03-18
tags:
    - attack.defense-impairment
    - attack.t1685
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/service'
            - '/systemctl'
            - '/chkconfig'
        CommandLine|contains:
            - ' stop '
            - ' disable '
    filter_main_legit_snapd:
        Image|endswith: '/systemctl'
        CommandLine|contains:
            - '--no-reload disable snap-snapd-'
            - ' stop snap-snapd-'
    filter_main_ssh_preinstall:
        Image|endswith: '/systemctl'
        ParentCommandLine|contains: 'tmp.ci/preinst upgrade'
        CommandLine|contains|all:
            - ' stop '
            - 'ssh.'
    filter_main_ubuntu_upgrade:
        ParentCommandLine|contains: '/dpkg/info/ubuntu-pro-client.prerm upgrade'
        Image|endswith: '/systemctl'
    filter_optional_aws_agent:
        Image|endswith: '/systemctl'
        CommandLine|endswith: 'snap.amazon-ssm-agent.amazon-ssm-agent.service'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate administration activities
    - Some false positives are to be expected. Apply additional filters as needed before pushing to production.
level: medium
```
