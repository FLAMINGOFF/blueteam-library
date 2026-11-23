---
title: Potential RDP Tunneling Via Plink
summary: Execution of plink to perform data exfiltration and tunneling
sigma_id: f38ce0b9-5e97-4b47-a211-7dc8d8b871da
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1572
author: Florian Roth (Nextron Systems)
date: '2022-08-04'
modified: '2023-01-27'
falsepositives:
  - Unknown
references:
  - https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_plink_susp_tunneling.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential RDP Tunneling Via Plink
id: f38ce0b9-5e97-4b47-a211-7dc8d8b871da
related:
    - id: f7d7ebd5-a016-46e2-9c54-f9932f2d386d # ssh.exe
      type: similar
status: test
description: Execution of plink to perform data exfiltration and tunneling
references:
    - https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
author: Florian Roth (Nextron Systems)
date: 2022-08-04
modified: 2023-01-27
tags:
    - attack.command-and-control
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        Image|endswith: '\plink.exe'
        CommandLine|contains: ':127.0.0.1:3389'
    selection_b1:
        Image|endswith: '\plink.exe'
        CommandLine|contains: ':3389'
    selection_b2:
        CommandLine|contains:
            - ' -P 443'
            - ' -P 22'
    condition: selection_a or all of selection_b*
falsepositives:
    - Unknown
level: high
```
