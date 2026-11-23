---
title: JScript Compiler Execution
summary: |-
  Detects the execution of the "jsc.exe" (JScript Compiler).
  Attacker might abuse this in order to compile JScript files on the fly and bypassing application whitelisting.
sigma_id: 52788a70-f1da-40dd-8fbd-73b5865d6568
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: frack113
date: '2022-05-02'
modified: '2024-04-24'
falsepositives:
  - Legitimate use to compile JScript by developers.
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Jsc/
  - https://www.phpied.com/make-your-javascript-a-windows-exe/
  - https://twitter.com/DissectMalware/status/998797808907046913
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_jsc_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: JScript Compiler Execution
id: 52788a70-f1da-40dd-8fbd-73b5865d6568
status: test
description: |
    Detects the execution of the "jsc.exe" (JScript Compiler).
    Attacker might abuse this in order to compile JScript files on the fly and bypassing application whitelisting.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Jsc/
    - https://www.phpied.com/make-your-javascript-a-windows-exe/
    - https://twitter.com/DissectMalware/status/998797808907046913
author: frack113
date: 2022-05-02
modified: 2024-04-24
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Image|endswith: '\jsc.exe'
        - OriginalFileName: 'jsc.exe'
    condition: selection
falsepositives:
    - Legitimate use to compile JScript by developers.
# Note: Can be decreased to informational or increased to medium depending on how this utility is used.
level: low
```
