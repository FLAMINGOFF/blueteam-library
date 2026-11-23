---
title: Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE
summary: Detects the start of a non built-in assistive technology applications via "Atbroker.EXE".
sigma_id: f24bcaea-0cd1-11eb-adc1-0242ac120002
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Mateusz Wydra, oscd.community
date: '2020-10-12'
modified: '2024-03-06'
falsepositives:
  - Legitimate, non-default assistive technology applications execution
references:
  - http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
  - https://lolbas-project.github.io/lolbas/Binaries/Atbroker/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_atbroker_uncommon_ats_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE
id: f24bcaea-0cd1-11eb-adc1-0242ac120002
status: test
description: Detects the start of a non built-in assistive technology applications via "Atbroker.EXE".
references:
    - http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
    - https://lolbas-project.github.io/lolbas/Binaries/Atbroker/
author: Mateusz Wydra, oscd.community
date: 2020-10-12
modified: 2024-03-06
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\AtBroker.exe'
        - OriginalFileName: 'AtBroker.exe'
    selection_cli:
        CommandLine|contains: 'start'
    filter_main_builtin:
        CommandLine|contains:
            - 'animations'
            - 'audiodescription'
            - 'caretbrowsing'
            - 'caretwidth'
            - 'colorfiltering'
            - 'cursorindicator'
            - 'cursorscheme'
            - 'filterkeys'
            - 'focusborderheight'
            - 'focusborderwidth'
            - 'highcontrast'
            - 'keyboardcues'
            - 'keyboardpref'
            - 'livecaptions'
            - 'magnifierpane'
            - 'messageduration'
            - 'minimumhitradius'
            - 'mousekeys'
            - 'Narrator'
            - 'osk'
            - 'overlappedcontent'
            - 'showsounds'
            - 'soundsentry'
            - 'speechreco'
            - 'stickykeys'
            - 'togglekeys'
            - 'voiceaccess'
            - 'windowarranging'
            - 'windowtracking'
            - 'windowtrackingtimeout'
            - 'windowtrackingzorder'
    filter_optional_java:
        CommandLine|contains: 'Oracle_JavaAccessBridge'
    condition: all of selection_* and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate, non-default assistive technology applications execution
level: medium
```
