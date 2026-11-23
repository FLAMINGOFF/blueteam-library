---
title: Suspicious FromBase64String Usage On Gzip Archive - Process Creation
summary: Detects attempts of decoding a base64 Gzip archive via PowerShell. This technique is often used as a method to load malicious content into memory afterward.
sigma_id: d75d6b6b-adb9-48f7-824b-ac2e786efe1f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1132.001
author: frack113
date: '2022-12-23'
falsepositives:
  - Legitimate administrative script
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=43
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_frombase64string_archive.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious FromBase64String Usage On Gzip Archive - Process Creation
id: d75d6b6b-adb9-48f7-824b-ac2e786efe1f
related:
    - id: df69cb1d-b891-4cd9-90c7-d617d90100ce
      type: similar
status: test
description: Detects attempts of decoding a base64 Gzip archive via PowerShell. This technique is often used as a method to load malicious content into memory afterward.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=43
author: frack113
date: 2022-12-23
tags:
    - attack.command-and-control
    - attack.t1132.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'FromBase64String'
            - 'MemoryStream'
            - 'H4sI'
    condition: selection
falsepositives:
    - Legitimate administrative script
level: medium
```
