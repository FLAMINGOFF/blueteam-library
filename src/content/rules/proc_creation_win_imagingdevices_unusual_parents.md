---
title: ImagingDevices Unusual Parent/Child Processes
summary: Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity
sigma_id: f11f2808-adb4-46c0-802a-8660db50fa99
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-27'
modified: '2022-12-29'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_imagingdevices_unusual_parents.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: ImagingDevices Unusual Parent/Child Processes
id: f11f2808-adb4-46c0-802a-8660db50fa99
status: test
description: Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity
references:
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-27
modified: 2022-12-29
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
        Image|endswith: '\ImagingDevices.exe'
    selection_child:
        # You can add specific suspicious child processes (such as cmd, powershell...) to increase the accuracy
        ParentImage|endswith: '\ImagingDevices.exe'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
