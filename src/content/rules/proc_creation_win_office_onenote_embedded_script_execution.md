---
title: OneNote.EXE Execution of Malicious Embedded Scripts
summary: |-
  Detects the execution of malicious OneNote documents that contain embedded scripts.
  When a user clicks on a OneNote attachment and then on the malicious link inside the ".one" file, it exports and executes the malicious embedded script from specific directories.
sigma_id: 84b1706c-932a-44c4-ae28-892b28a25b94
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.001
author: '@kostastsale'
date: '2023-02-02'
falsepositives:
  - Unlikely
references:
  - https://bazaar.abuse.ch/browse/tag/one/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_office_onenote_embedded_script_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: OneNote.EXE Execution of Malicious Embedded Scripts
id: 84b1706c-932a-44c4-ae28-892b28a25b94
status: test
description: |
    Detects the execution of malicious OneNote documents that contain embedded scripts.
    When a user clicks on a OneNote attachment and then on the malicious link inside the ".one" file, it exports and executes the malicious embedded script from specific directories.
references:
    - https://bazaar.abuse.ch/browse/tag/one/
author: '@kostastsale'
date: 2023-02-02
tags:
    - attack.stealth
    - attack.t1218.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\onenote.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
        CommandLine|contains:
            - '\exported\'
            - '\onenoteofflinecache_files\'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
