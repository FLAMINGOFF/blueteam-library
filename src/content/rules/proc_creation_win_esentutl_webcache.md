---
title: Esentutl Steals Browser Information
summary: One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe
sigma_id: 6a69f62d-ce75-4b57-8dce-6351eb55b362
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1005
author: frack113
date: '2022-02-13'
modified: '2024-03-05'
falsepositives:
  - Legitimate use
references:
  - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
  - https://redcanary.com/threat-detection-report/threats/qbot/
  - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_esentutl_webcache.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Esentutl Steals Browser Information
id: 6a69f62d-ce75-4b57-8dce-6351eb55b362
status: test
description: One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
    - https://redcanary.com/threat-detection-report/threats/qbot/
    - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
author: frack113
date: 2022-02-13
modified: 2024-03-05
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\esentutl.exe'
        - OriginalFileName: 'esentutl.exe'
    selection_flag:
        CommandLine|contains|windash: '-r'
    selection_webcache:
        CommandLine|contains: '\Windows\WebCache'
    condition: all of selection*
falsepositives:
    - Legitimate use
level: medium
```
