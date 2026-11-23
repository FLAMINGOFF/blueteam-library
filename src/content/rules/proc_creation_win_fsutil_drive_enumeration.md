---
title: Fsutil Drive Enumeration
summary: Attackers may leverage fsutil to enumerated connected drives.
sigma_id: 63de06b9-a385-40b5-8b32-73f2b9ef84b6
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1120
author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: '2022-03-29'
modified: '2022-07-14'
falsepositives:
  - Certain software or administrative tasks may trigger false positives.
references:
  - Turla has used fsutil fsinfo drives to list connected drives.
  - https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/discovery_peripheral_device.toml
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_fsutil_drive_enumeration.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Fsutil Drive Enumeration
id: 63de06b9-a385-40b5-8b32-73f2b9ef84b6
status: test
description: Attackers may leverage fsutil to enumerated connected drives.
references:
    - Turla has used fsutil fsinfo drives to list connected drives.
    - https://github.com/elastic/detection-rules/blob/414d32027632a49fb239abb8fbbb55d3fa8dd861/rules/windows/discovery_peripheral_device.toml
author: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: 2022-03-29
modified: 2022-07-14
tags:
    - attack.discovery
    - attack.t1120
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\fsutil.exe'
        - OriginalFileName: 'fsutil.exe'
    selection_cli:
        CommandLine|contains: 'drives'
    condition: all of selection_*
falsepositives:
    - Certain software or administrative tasks may trigger false positives.
level: low
```
