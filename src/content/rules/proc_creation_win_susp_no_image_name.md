---
title: Process Launched Without Image Name
summary: Detect the use of processes with no name (".exe"), which can be used to evade Image-based detections.
sigma_id: f208d6d8-d83a-4c2c-960d-877c37da84e5
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: Matt Anderson (Huntress)
date: '2024-07-23'
falsepositives:
  - Rare legitimate software.
references:
  - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_no_image_name.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Process Launched Without Image Name
id: f208d6d8-d83a-4c2c-960d-877c37da84e5
status: test
description: Detect the use of processes with no name (".exe"), which can be used to evade Image-based detections.
references:
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Matt Anderson (Huntress)
date: 2024-07-23
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\.exe'
    condition: selection
falsepositives:
    - Rare legitimate software.
level: medium
```
