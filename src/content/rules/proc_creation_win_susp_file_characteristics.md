---
title: Suspicious File Characteristics Due to Missing Fields
summary: Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe
sigma_id: 9637e8a5-7131-4f7f-bdc7-2b05d8670c43
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.006
author: Markus Neis, Sander Wiebing
date: '2018-11-22'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://securelist.com/muddywater/88059/
  - https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_file_characteristics.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious File Characteristics Due to Missing Fields
id: 9637e8a5-7131-4f7f-bdc7-2b05d8670c43
status: test
description: Detects Executables in the Downloads folder without FileVersion,Description,Product,Company likely created with py2exe
references:
    - https://securelist.com/muddywater/88059/
    - https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection
author: Markus Neis, Sander Wiebing
date: 2018-11-22
modified: 2022-10-09
tags:
    - attack.execution
    - attack.t1059.006
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        Description: '\?'
        FileVersion: '\?'
    selection2:
        Description: '\?'
        Product: '\?'
    selection3:
        Description: '\?'
        Company: '\?'
    folder:
        Image|contains: '\Downloads\'
    condition: (selection1 or selection2 or selection3) and folder
falsepositives:
    - Unknown
level: medium
```
