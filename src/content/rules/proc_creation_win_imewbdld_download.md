---
title: Arbitrary File Download Via IMEWDBLD.EXE
summary: Detects usage of "IMEWDBLD.exe" to download arbitrary files
sigma_id: 863218bd-c7d0-4c52-80cd-0a96c09f54af
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1218
author: Swachchhanda Shrawan Poudel
date: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-10---windows---powershell-download
  - https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_imewbdld_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary File Download Via IMEWDBLD.EXE
id: 863218bd-c7d0-4c52-80cd-0a96c09f54af
related:
    - id: 8d7e392e-9b28-49e1-831d-5949c6281228
      type: derived
status: test
description: Detects usage of "IMEWDBLD.exe" to download arbitrary files
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1105/T1105.md#atomic-test-10---windows---powershell-download
    - https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/
author: Swachchhanda Shrawan Poudel
date: 2023-11-09
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\IMEWDBLD.exe'
        - OriginalFileName: 'imewdbld.exe'
    selection_cli:
        CommandLine|contains:
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
# Note: Please reduce this to medium if you find legitimate use case of this utility with a URL
level: high
```
