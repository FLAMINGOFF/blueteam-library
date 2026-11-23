---
title: PUA - Chisel Tunneling Tool Execution
summary: Detects usage of the Chisel tunneling tool via the commandline arguments
sigma_id: 8b0e12da-d3c3-49db-bb4f-256703f380e5
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1090.001
author: Florian Roth (Nextron Systems)
date: '2022-09-13'
modified: '2023-02-13'
falsepositives:
  - Some false positives may occur with other tools with similar commandlines
references:
  - https://github.com/jpillora/chisel/
  - https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in/
  - https://blog.sekoia.io/lucky-mouse-incident-response-to-detection-engineering/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_chisel.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - Chisel Tunneling Tool Execution
id: 8b0e12da-d3c3-49db-bb4f-256703f380e5
related:
    - id: cf93e05e-d798-4d9e-b522-b0248dc61eaf
      type: similar
status: test
description: Detects usage of the Chisel tunneling tool via the commandline arguments
references:
    - https://github.com/jpillora/chisel/
    - https://arcticwolf.com/resources/blog/lorenz-ransomware-chiseling-in/
    - https://blog.sekoia.io/lucky-mouse-incident-response-to-detection-engineering/
author: Florian Roth (Nextron Systems)
date: 2022-09-13
modified: 2023-02-13
tags:
    - attack.command-and-control
    - attack.t1090.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\chisel.exe'
    selection_param1:
        CommandLine|contains:
            - 'exe client '
            - 'exe server '
    selection_param2:
        CommandLine|contains:
            - '-socks5'
            - '-reverse'
            - ' r:'
            - ':127.0.0.1:'
            - '-tls-skip-verify '
            - ':socks'
    condition: selection_img or all of selection_param*
falsepositives:
    - Some false positives may occur with other tools with similar commandlines
level: high
```
