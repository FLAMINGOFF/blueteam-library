---
title: Potentially Suspicious Execution From Tmp Folder
summary: Detects a potentially suspicious execution of a process located in the '/tmp/' folder
sigma_id: 312b42b1-bded-4441-8b58-163a3af58775
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1036
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: '2023-06-02'
modified: '2025-08-05'
falsepositives:
  - Unknown
references:
  - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
  - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
  - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
  - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_execution_tmp_folder.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Execution From Tmp Folder
id: 312b42b1-bded-4441-8b58-163a3af58775
status: test
description: Detects a potentially suspicious execution of a process located in the '/tmp/' folder
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
modified: 2025-08-05
tags:
    - attack.stealth
    - attack.t1036
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|startswith: '/tmp/'
    filter_optional_nextcloud:
        Image|endswith: '/usr/bin/nextcloud'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
