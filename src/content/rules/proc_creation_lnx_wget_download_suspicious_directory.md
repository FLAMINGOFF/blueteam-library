---
title: Download File To Potentially Suspicious Directory Via Wget
summary: Detects the use of wget to download content to a suspicious directory
sigma_id: cf610c15-ed71-46e1-bdf8-2bd1a99de6c4
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: '2023-06-02'
falsepositives:
  - Unknown
references:
  - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
  - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
  - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
  - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_wget_download_suspicious_directory.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Download File To Potentially Suspicious Directory Via Wget
id: cf610c15-ed71-46e1-bdf8-2bd1a99de6c4
status: test
description: Detects the use of wget to download content to a suspicious directory
references:
    - https://blogs.jpcert.or.jp/en/2023/05/gobrat.html
    - https://jstnk9.github.io/jstnk9/research/GobRAT-Malware/
    - https://www.virustotal.com/gui/file/60bcd645450e4c846238cf0e7226dc40c84c96eba99f6b2cffcd0ab4a391c8b3/detection
    - https://www.virustotal.com/gui/file/3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1/detection
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-06-02
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/wget'
    selection_output:
        - CommandLine|re: '\s-O\s' # We use regex to ensure a case sensitive argument detection
        - CommandLine|contains: '--output-document'
    selection_path:
        CommandLine|contains: '/tmp/'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
