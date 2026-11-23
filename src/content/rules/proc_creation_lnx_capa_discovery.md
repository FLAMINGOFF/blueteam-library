---
title: Capabilities Discovery - Linux
summary: Detects usage of "getcap" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other.
sigma_id: d8d97d51-122d-4cdd-9e2f-01b4b4933530
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
techniques:
  - T1083
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-12-28'
modified: '2026-01-24'
falsepositives:
  - Unknown
references:
  - https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
  - https://github.com/carlospolop/PEASS-ng
  - https://github.com/diego-treitos/linux-smart-enumeration
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_capa_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Capabilities Discovery - Linux
id: d8d97d51-122d-4cdd-9e2f-01b4b4933530
status: test
description: Detects usage of "getcap" binary. This is often used during recon activity to determine potential binaries that can be abused as GTFOBins or other.
references:
    - https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
    - https://github.com/carlospolop/PEASS-ng
    - https://github.com/diego-treitos/linux-smart-enumeration
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-28
modified: 2026-01-24
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/getcap'
        CommandLine|contains: ' -r '
    condition: selection
falsepositives:
    - Unknown
level: low
```
