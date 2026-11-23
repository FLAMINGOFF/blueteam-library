---
title: Suspicious Execution of Hostname
summary: Use of hostname to get information
sigma_id: 7be5fb68-f9ef-476d-8b51-0256ebece19e
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1082
author: frack113
date: '2022-01-01'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-6---hostname-discovery-windows
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/hostname
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hostname_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Execution of Hostname
id: 7be5fb68-f9ef-476d-8b51-0256ebece19e
status: test
description: Use of hostname to get information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-6---hostname-discovery-windows
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/hostname
author: frack113
date: 2022-01-01
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\HOSTNAME.EXE'
    condition: selection
falsepositives:
    - Unknown
level: low
```
