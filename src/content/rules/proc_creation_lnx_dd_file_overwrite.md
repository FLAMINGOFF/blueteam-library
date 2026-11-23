---
title: DD File Overwrite
summary: Detects potential overwriting and deletion of a file using DD.
sigma_id: 2953194b-e33c-4859-b9e8-05948c167447
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0040
techniques:
  - T1485
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: '2021-10-15'
modified: '2022-07-07'
falsepositives:
  - Any user deleting files that way.
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md#atomic-test-2---macoslinux---overwrite-file-with-dd
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_dd_file_overwrite.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DD File Overwrite
id: 2953194b-e33c-4859-b9e8-05948c167447
status: test
description: Detects potential overwriting and deletion of a file using DD.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md#atomic-test-2---macoslinux---overwrite-file-with-dd
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-10-15
modified: 2022-07-07
tags:
    - attack.impact
    - attack.t1485
logsource:
    product: linux
    category: process_creation
detection:
    selection1:
        Image:
            - '/bin/dd'
            - '/usr/bin/dd'
    selection2:
        CommandLine|contains: 'of='
    selection3:
        CommandLine|contains:
            - 'if=/dev/zero'
            - 'if=/dev/null'
    condition: all of selection*
falsepositives:
    - Any user deleting files that way.
level: low
```
