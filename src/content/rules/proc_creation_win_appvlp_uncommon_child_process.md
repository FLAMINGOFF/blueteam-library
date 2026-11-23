---
title: Uncommon Child Process Of Appvlp.EXE
summary: |-
  Detects uncommon child processes of Appvlp.EXE
  Appvlp or the Application Virtualization Utility is included with Microsoft Office. Attackers are able to abuse "AppVLP" to execute shell commands.
  Normally, this binary is used for Application Virtualization, but it can also be abused to circumvent the ASR file path rule folder
  or to mark a file as a system file.
sigma_id: 9c7e131a-0f2c-4ae0-9d43-b04f4e266d43
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0002
techniques:
  - T1218
author: Sreeman
date: '2020-03-13'
modified: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Appvlp/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_appvlp_uncommon_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Child Process Of Appvlp.EXE
id: 9c7e131a-0f2c-4ae0-9d43-b04f4e266d43
status: test
description: |
    Detects uncommon child processes of Appvlp.EXE
    Appvlp or the Application Virtualization Utility is included with Microsoft Office. Attackers are able to abuse "AppVLP" to execute shell commands.
    Normally, this binary is used for Application Virtualization, but it can also be abused to circumvent the ASR file path rule folder
    or to mark a file as a system file.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Appvlp/
author: Sreeman
date: 2020-03-13
modified: 2023-11-09
tags:
    - attack.stealth
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\appvlp.exe'
    # Note: Filters based on data from EchoTrail: https://www.echotrail.io/insights/search/appvlp.exe/
    filter_main_generic:
        Image|endswith:
            - ':\Windows\SysWOW64\rundll32.exe'
            - ':\Windows\System32\rundll32.exe'
    filter_optional_office_msoasb:
        Image|contains: ':\Program Files\Microsoft Office'
        Image|endswith: '\msoasb.exe'
    filter_optional_office_skype:
        Image|contains|all:
            - ':\Program Files\Microsoft Office'
            - '\SkypeSrv\'
        Image|endswith: '\SKYPESERVER.EXE'
    filter_optional_office_msouc:
        Image|contains: ':\Program Files\Microsoft Office'
        Image|endswith: '\MSOUC.EXE'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
