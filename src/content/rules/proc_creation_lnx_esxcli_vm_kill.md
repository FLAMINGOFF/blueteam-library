---
title: ESXi VM Kill Via ESXCLI
summary: Detects execution of the "esxcli" command with the "vm" and "kill" flag in order to kill/shutdown a specific VM.
sigma_id: 2992ac4d-31e9-4325-99f2-b18a73221bb2
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
  - TA0040
techniques:
  - T1059.012
  - T1529
author: Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon
date: '2023-09-04'
falsepositives:
  - Legitimate administration activities
references:
  - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
  - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_vm.html
  - https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/
  - https://www.trendmicro.com/en_us/research/22/e/new-linux-based-ransomware-cheerscrypt-targets-exsi-devices.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_esxcli_vm_kill.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: ESXi VM Kill Via ESXCLI
id: 2992ac4d-31e9-4325-99f2-b18a73221bb2
status: test
description: Detects execution of the "esxcli" command with the "vm" and "kill" flag in order to kill/shutdown a specific VM.
references:
    - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_vm.html
    - https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/
    - https://www.trendmicro.com/en_us/research/22/e/new-linux-based-ransomware-cheerscrypt-targets-exsi-devices.html
author: Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon
date: 2023-09-04
tags:
    - attack.execution
    - attack.impact
    - attack.t1059.012
    - attack.t1529
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains|all:
            - 'vm process'
            - 'kill'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
