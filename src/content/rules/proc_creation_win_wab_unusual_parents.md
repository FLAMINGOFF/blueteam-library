---
title: Wab/Wabmig Unusual Parent Or Child Processes
summary: Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity
sigma_id: 63d1ccc0-2a43-4f4b-9289-361b308991ff
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-12'
modified: '2022-09-27'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bumblebee-loader-cybercrime
  - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wab_unusual_parents.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Wab/Wabmig Unusual Parent Or Child Processes
id: 63d1ccc0-2a43-4f4b-9289-361b308991ff
status: test
description: Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity
references:
    - https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bumblebee-loader-cybercrime
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-12
modified: 2022-09-27
tags:
    - attack.execution
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            # Add more if known
            - \WmiPrvSE.exe
            - \svchost.exe
            - \dllhost.exe
        Image|endswith:
            - '\wab.exe'
            - '\wabmig.exe' # (Microsoft Address Book Import Tool)
    selection_child:
        # You can add specific suspicious child processes (such as cmd, powershell...) to increase the accuracy
        ParentImage|endswith:
            - '\wab.exe'
            - '\wabmig.exe' # (Microsoft Address Book Import Tool)
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
