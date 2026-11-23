---
title: Clipboard Collection with Xclip Tool
summary: |-
  Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed.
  Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.
sigma_id: ec127035-a636-4b9a-8555-0efd4e59f316
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0009
techniques:
  - T1115
author: Pawel Mazur, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: '2021-10-15'
modified: '2022-09-15'
falsepositives:
  - Legitimate usage of xclip tools.
references:
  - https://www.packetlabs.net/posts/clipboard-data-security/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_clipboard_collection.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Clipboard Collection with Xclip Tool
id: ec127035-a636-4b9a-8555-0efd4e59f316
status: test
description: |
    Detects attempts to collect data stored in the clipboard from users with the usage of xclip tool. Xclip has to be installed.
    Highly recommended using rule on servers, due to high usage of clipboard utilities on user workstations.
references:
    - https://www.packetlabs.net/posts/clipboard-data-security/
author: Pawel Mazur, Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-10-15
modified: 2022-09-15
tags:
    - attack.collection
    - attack.t1115
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|contains: 'xclip'
        CommandLine|contains|all:
            - '-sel'
            - 'clip'
            - '-o'
    condition: selection
falsepositives:
    - Legitimate usage of xclip tools.
level: low
```
