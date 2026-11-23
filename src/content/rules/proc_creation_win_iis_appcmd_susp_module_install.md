---
title: IIS Native-Code Module Command Line Installation
summary: Detects suspicious IIS native-code module installations via command line
sigma_id: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
techniques:
  - T1505.003
author: Florian Roth (Nextron Systems)
date: '2019-12-11'
modified: '2024-03-13'
falsepositives:
  - Unknown as it may vary from organisation to organisation how admins use to install IIS modules
references:
  - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
  - https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_iis_appcmd_susp_module_install.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: IIS Native-Code Module Command Line Installation
id: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
status: test
description: Detects suspicious IIS native-code module installations via command line
references:
    - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
    - https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
author: Florian Roth (Nextron Systems)
date: 2019-12-11
modified: 2024-03-13
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\appcmd.exe'
        - OriginalFileName: 'appcmd.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'install'
            - 'module'
        CommandLine|contains|windash: '-name:'
    filter_iis_setup:
        ParentImage: 'C:\Windows\System32\inetsrv\iissetup.exe'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Unknown as it may vary from organisation to organisation how admins use to install IIS modules
level: medium
```
