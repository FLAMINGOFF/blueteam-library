---
title: Phishing Pattern ISO in Archive
summary: >-
  Detects cases in which an ISO files is opened within an archiver like 7Zip or Winrar, which is a sign of phishing as threat actors put small ISO files in archives as email attachments to bypass
  certain filters and protective measures (mark of web)
sigma_id: fcdf69e5-a3d3-452a-9724-26f2308bf2b1
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0001
techniques:
  - T1566
author: Florian Roth (Nextron Systems)
date: '2022-06-07'
falsepositives:
  - Legitimate cases in which archives contain ISO or IMG files and the user opens the archive and the image via clicking and not extraction
references:
  - https://twitter.com/1ZRR4H/status/1534259727059787783
  - https://app.any.run/tasks/e1fe6a62-bce8-4323-a49a-63795d9afd5d/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_archiver_iso_phishing.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Phishing Pattern ISO in Archive
id: fcdf69e5-a3d3-452a-9724-26f2308bf2b1
status: test
description: Detects cases in which an ISO files is opened within an archiver like 7Zip or Winrar, which is a sign of phishing as threat actors put small ISO files in archives as email attachments to bypass certain filters and protective measures (mark of web)
references:
    - https://twitter.com/1ZRR4H/status/1534259727059787783
    - https://app.any.run/tasks/e1fe6a62-bce8-4323-a49a-63795d9afd5d/
author: Florian Roth (Nextron Systems)
date: 2022-06-07
tags:
    - attack.initial-access
    - attack.t1566
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\Winrar.exe'
            - '\7zFM.exe'
            - '\peazip.exe'
        Image|endswith:
            - '\isoburn.exe'
            - '\PowerISO.exe'
            - '\ImgBurn.exe'
    condition: selection
falsepositives:
    - Legitimate cases in which archives contain ISO or IMG files and the user opens the archive and the image via clicking and not extraction
level: high
```
