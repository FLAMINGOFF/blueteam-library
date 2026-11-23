---
title: Suspicious Child Process of Notepad++ Updater - GUP.Exe
summary: |-
  Detects suspicious child process creation by the Notepad++ updater process (gup.exe).
  This could indicate potential exploitation of the updater component to deliver unwanted malware.
sigma_id: bb0e87ce-c89f-4857-84fa-095e4483e9cb
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
  - TA0006
  - TA0001
techniques:
  - T1195.002
  - T1557
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2026-02-03'
falsepositives:
  - Unlikely
references:
  - https://notepad-plus-plus.org/news/v889-released/
  - https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
  - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
  - https://www.validin.com/blog/exploring_notepad_plus_plus_network_indicators/
  - https://securelist.com/notepad-supply-chain-attack/118708/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_gup_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Child Process of Notepad++ Updater - GUP.Exe
id: bb0e87ce-c89f-4857-84fa-095e4483e9cb
status: experimental
description: |
    Detects suspicious child process creation by the Notepad++ updater process (gup.exe).
    This could indicate potential exploitation of the updater component to deliver unwanted malware.
references:
    - https://notepad-plus-plus.org/news/v889-released/
    - https://www.heise.de/en/news/Notepad-updater-installed-malware-11109726.html
    - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
    - https://www.validin.com/blog/exploring_notepad_plus_plus_network_indicators/
    - https://securelist.com/notepad-supply-chain-attack/118708/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-02-03
tags:
    - attack.collection
    - attack.credential-access
    - attack.t1195.002
    - attack.initial-access
    - attack.t1557
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\gup.exe'
    selection_child_img:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\mshta.exe'
    selection_child_cli:
        CommandLine|contains:
            - 'bitsadmin'
            - 'certutil'
            - 'curl'
            - 'finger'
            - 'forfiles'
            - 'regsvr32'
            - 'rundll32'
            - 'wget'
    condition: selection_parent and 1 of selection_child_*
falsepositives:
    - Unlikely
level: high
```
