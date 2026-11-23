---
title: UAC Bypass Using Event Viewer RecentViews
summary: Detects the pattern of UAC Bypass using Event Viewer RecentViews
sigma_id: 30fc8de7-d833-40c4-96b6-28319fbc4f6c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-11-22'
falsepositives:
  - Unknown
references:
  - https://twitter.com/orange_8361/status/1518970259868626944
  - https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#execute
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_uac_bypass_eventvwr_recentviews.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UAC Bypass Using Event Viewer RecentViews
id: 30fc8de7-d833-40c4-96b6-28319fbc4f6c
related:
    - id: 63e4f530-65dc-49cc-8f80-ccfa95c69d43
      type: similar
status: test
description: Detects the pattern of UAC Bypass using Event Viewer RecentViews
references:
    - https://twitter.com/orange_8361/status/1518970259868626944
    - https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/#execute
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-11-22
tags:
    - attack.privilege-escalation
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_path:
        # Example: ysoserial.exe -o raw -f BinaryFormatter - g DataSet -c calc > RecentViews & copy RecentViews %LOCALAPPDATA%\Microsoft\EventV~1\RecentViews & eventvwr.exe
        CommandLine|contains:
            - '\Event Viewer\RecentViews'
            - '\EventV~1\RecentViews'
    selection_redirect:
        CommandLine|contains: '>'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
