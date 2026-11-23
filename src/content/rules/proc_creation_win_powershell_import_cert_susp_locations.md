---
title: Root Certificate Installed From Susp Locations
summary: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
sigma_id: 5f6a601c-2ecb-498b-9c33-660362323afa
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1553.004
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-09'
modified: '2023-01-16'
falsepositives:
  - Unlikely
references:
  - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
  - https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2022-ps
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_import_cert_susp_locations.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Root Certificate Installed From Susp Locations
id: 5f6a601c-2ecb-498b-9c33-660362323afa
status: test
description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
references:
    - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
    - https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2022-ps
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
modified: 2023-01-16
tags:
    - attack.defense-impairment
    - attack.t1553.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'Import-Certificate'
            - ' -FilePath '
            - 'Cert:\LocalMachine\Root'
        CommandLine|contains:
            - '\AppData\Local\Temp\'
            - ':\Windows\TEMP\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Perflogs\'
            - ':\Users\Public\'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
