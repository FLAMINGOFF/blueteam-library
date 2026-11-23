---
title: Terminal Service Process Spawn
summary: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
sigma_id: 1012f107-b8f1-4271-af30-5aed2de89b39
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0001
  - TA0008
techniques:
  - T1190
  - T1210
author: Florian Roth (Nextron Systems)
date: '2019-05-22'
modified: '2023-01-25'
falsepositives:
  - Unknown
references:
  - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_svchost_termserv_proc_spawn.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Terminal Service Process Spawn
id: 1012f107-b8f1-4271-af30-5aed2de89b39
status: test
description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
references:
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/rdp-stands-for-really-do-patch-understanding-the-wormable-rdp-vulnerability-cve-2019-0708/
author: Florian Roth (Nextron Systems)
date: 2019-05-22
modified: 2023-01-25
tags:
    - attack.initial-access
    - attack.t1190
    - attack.lateral-movement
    - attack.t1210
    - car.2013-07-002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentCommandLine|contains|all:
            - '\svchost.exe'
            - 'termsvcs'
    filter_img:
        Image|endswith:
            - '\rdpclip.exe'
            - ':\Windows\System32\csrss.exe'
            - ':\Windows\System32\wininit.exe'
            - ':\Windows\System32\winlogon.exe'
    filter_null:
        Image: null
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high
```
