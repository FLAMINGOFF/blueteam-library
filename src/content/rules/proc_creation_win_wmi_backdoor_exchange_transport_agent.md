---
title: WMI Backdoor Exchange Transport Agent
summary: Detects a WMI backdoor in Exchange Transport Agents via WMI event filters
sigma_id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
techniques:
  - T1546.003
author: Florian Roth (Nextron Systems)
date: '2019-10-11'
modified: '2023-02-08'
falsepositives:
  - Unknown
references:
  - https://twitter.com/cglyer/status/1182389676876980224
  - https://twitter.com/cglyer/status/1182391019633029120
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmi_backdoor_exchange_transport_agent.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: WMI Backdoor Exchange Transport Agent
id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: test
description: Detects a WMI backdoor in Exchange Transport Agents via WMI event filters
references:
    - https://twitter.com/cglyer/status/1182389676876980224
    - https://twitter.com/cglyer/status/1182391019633029120
author: Florian Roth (Nextron Systems)
date: 2019-10-11
modified: 2023-02-08
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1546.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\EdgeTransport.exe'
    filter_conhost:
        Image: 'C:\Windows\System32\conhost.exe'
    filter_oleconverter:  # FP also documented in https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=18
        Image|startswith: 'C:\Program Files\Microsoft\Exchange Server\'
        Image|endswith: '\Bin\OleConverter.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: critical
```
