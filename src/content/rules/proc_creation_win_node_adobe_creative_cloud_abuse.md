---
title: Node Process Executions
summary: Detects the execution of other scripts using the Node executable packaged with Adobe Creative Cloud
sigma_id: df1f26d3-bea7-4700-9ea2-ad3e990cf90e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
  - T1059.007
author: Max Altgelt (Nextron Systems)
date: '2022-04-06'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20220406203641/https://twitter.com/mttaggart/status/1511804863293784064
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_node_adobe_creative_cloud_abuse.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Node Process Executions
id: df1f26d3-bea7-4700-9ea2-ad3e990cf90e
status: test
description: Detects the execution of other scripts using the Node executable packaged with Adobe Creative Cloud
references:
    - https://web.archive.org/web/20220406203641/https://twitter.com/mttaggart/status/1511804863293784064
author: Max Altgelt (Nextron Systems)
date: 2022-04-06
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Adobe Creative Cloud Experience\libs\node.exe'
    filter:
        CommandLine|contains: 'Adobe Creative Cloud Experience\js' # Folder where Creative Cloud's JS resources are located
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
