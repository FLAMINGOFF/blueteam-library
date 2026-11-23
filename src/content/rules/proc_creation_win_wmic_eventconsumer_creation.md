---
title: NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE
summary: |-
  Detects the attempt to create an ActiveScriptEventConsumer via WMIC.EXE.
  An ActiveScriptEventConsumer is a built-in Windows Management Instrumentation (WMI) class that
  automatically executes a predefined script (in VBScript or JScript) whenever a specific system event occurs.
  Adversaries often abuse ActiveScriptEventConsumer to maintain persistence on a compromised host by executing a malicious script whenever a specific event occurs.
sigma_id: ebef4391-1a81-4761-a40a-1db446c0e625
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
techniques:
  - T1546.003
author: Florian Roth (Nextron Systems)
date: '2021-06-25'
modified: '2026-06-19'
falsepositives:
  - Legitimate software creating script event consumers
references:
  - https://twitter.com/johnlatwc/status/1408062131321270282?s=12
  - https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_eventconsumer_creation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE
id: ebef4391-1a81-4761-a40a-1db446c0e625
status: test
description: |
    Detects the attempt to create an ActiveScriptEventConsumer via WMIC.EXE.
    An ActiveScriptEventConsumer is a built-in Windows Management Instrumentation (WMI) class that
    automatically executes a predefined script (in VBScript or JScript) whenever a specific system event occurs.
    Adversaries often abuse ActiveScriptEventConsumer to maintain persistence on a compromised host by executing a malicious script whenever a specific event occurs.
references:
    - https://twitter.com/johnlatwc/status/1408062131321270282?s=12
    - https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
author: Florian Roth (Nextron Systems)
date: 2021-06-25
modified: 2026-06-19
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1546.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'wmic.exe'
        - Image|endswith: '\WMIC.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'ActiveScriptEventConsumer'
            - ' CREATE '
    condition: all of selection_*
falsepositives:
    - Legitimate software creating script event consumers
level: high
```
