---
title: Disabled IE Security Features
summary: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
sigma_id: fb50eb7a-5ab1-43ae-bcc9-091818cb8424
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: Florian Roth (Nextron Systems)
date: '2020-06-19'
modified: '2021-11-27'
falsepositives:
  - Unknown
references:
  - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_disable_ie_features.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Disabled IE Security Features
id: fb50eb7a-5ab1-43ae-bcc9-091818cb8424
status: test
description: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
references:
    - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
author: Florian Roth (Nextron Systems)
date: 2020-06-19
modified: 2021-11-27
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - ' -name IEHarden '
            - ' -value 0 '
    selection2:
        CommandLine|contains|all:
            - ' -name DEPOff '
            - ' -value 1 '
    selection3:
        CommandLine|contains|all:
            - ' -name DisableFirstRunCustomize '
            - ' -value 2 '
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
