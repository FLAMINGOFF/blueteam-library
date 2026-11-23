---
title: PUA - Adidnsdump Execution
summary: |-
  This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
  Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP
sigma_id: 26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1018
author: frack113
date: '2022-01-01'
modified: '2023-02-21'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md#atomic-test-9---remote-system-discovery---adidnsdump
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_python_adidnsdump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - Adidnsdump Execution
id: 26d3f0a2-f514-4a3f-a8a7-e7e48a8d9160
status: test
description: |
    This tool enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks Python 3 and python.exe must be installed,
    Usee to Query/modify DNS records for Active Directory integrated DNS via LDAP
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md#atomic-test-9---remote-system-discovery---adidnsdump
author: frack113
date: 2022-01-01
modified: 2023-02-21
tags:
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\python.exe'
        CommandLine|contains: 'adidnsdump'
    condition: selection
falsepositives:
    - Unknown
level: low
```
