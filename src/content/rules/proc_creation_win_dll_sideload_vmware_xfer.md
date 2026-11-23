---
title: DLL Sideloading by VMware Xfer Utility
summary: Detects execution of VMware Xfer utility (VMwareXferlogs.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL
sigma_id: ebea773c-a8f1-42ad-a856-00cb221966e8
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1574.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-02'
falsepositives:
  - Unlikely
references:
  - https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_dll_sideload_vmware_xfer.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DLL Sideloading by VMware Xfer Utility
id: ebea773c-a8f1-42ad-a856-00cb221966e8
status: test
description: Detects execution of VMware Xfer utility (VMwareXferlogs.exe) from the non-default directory which may be an attempt to sideload arbitrary DLL
references:
    - https://www.sentinelone.com/labs/lockbit-ransomware-side-loads-cobalt-strike-beacon-with-legitimate-vmware-utility/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-02
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\VMwareXferlogs.exe'
    filter: # VMware might be installed in another path so update the rule accordingly
        Image|startswith: 'C:\Program Files\VMware\'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
```
