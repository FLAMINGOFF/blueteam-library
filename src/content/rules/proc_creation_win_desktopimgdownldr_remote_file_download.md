---
title: Remote File Download Via Desktopimgdownldr Utility
summary: Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.
sigma_id: 214641c2-c579-4ecb-8427-0cf19df6842e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Tim Rauch, Elastic (idea)
date: '2022-09-27'
falsepositives:
  - Unknown
references:
  - https://www.elastic.co/guide/en/security/current/remote-file-download-via-desktopimgdownldr-utility.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_desktopimgdownldr_remote_file_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote File Download Via Desktopimgdownldr Utility
id: 214641c2-c579-4ecb-8427-0cf19df6842e
status: test
description: Detects the desktopimgdownldr utility being used to download a remote file. An adversary may use desktopimgdownldr to download arbitrary files as an alternative to certutil.
references:
    - https://www.elastic.co/guide/en/security/current/remote-file-download-via-desktopimgdownldr-utility.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\desktopimgdownldr.exe'
        ParentImage|endswith: '\desktopimgdownldr.exe'
        CommandLine|contains: '/lockscreenurl:http'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
