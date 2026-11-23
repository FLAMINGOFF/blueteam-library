---
title: ESXi Syslog Configuration Change Via ESXCLI
summary: Detects changes to the ESXi syslog configuration via "esxcli"
sigma_id: 38eb1dbb-011f-40b1-a126-cf03a0210563
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1685
  - T1690
  - T1059.012
author: Cedric Maurugeon
date: '2023-09-04'
falsepositives:
  - Legitimate administrative activities
references:
  - https://support.solarwinds.com/SuccessCenter/s/article/Configure-ESXi-Syslog-to-LEM?language=en_US
  - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_esxcli_syslog_config_change.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: ESXi Syslog Configuration Change Via ESXCLI
id: 38eb1dbb-011f-40b1-a126-cf03a0210563
status: test
description: Detects changes to the ESXi syslog configuration via "esxcli"
references:
    - https://support.solarwinds.com/SuccessCenter/s/article/Configure-ESXi-Syslog-to-LEM?language=en_US
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023-09-04
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1685
    - attack.t1690
    - attack.t1059.012
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains|all:
            - 'system'
            - 'syslog'
            - 'config'
        CommandLine|contains: ' set'
    condition: selection
falsepositives:
    - Legitimate administrative activities
level: medium
```
