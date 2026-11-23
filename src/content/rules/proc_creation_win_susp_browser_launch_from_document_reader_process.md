---
title: Potential Suspicious Browser Launch From Document Reader Process
summary: >-
  Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this
  could indicate a possible phishing attempt.
sigma_id: 1193d960-2369-499f-a158-7b50a31df682
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1204.002
author: Joseph Kamau
date: '2024-05-27'
modified: '2025-10-07'
falsepositives:
  - Unlikely in most cases, further investigation should be done in the commandline of the browser process to determine the context of the URL accessed.
references:
  - https://app.any.run/tasks/69c5abaa-92ad-45ba-8c53-c11e23e05d04/
  - https://app.any.run/tasks/64043a79-165f-4052-bcba-e6e49f847ec1/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_browser_launch_from_document_reader_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Suspicious Browser Launch From Document Reader Process
id: 1193d960-2369-499f-a158-7b50a31df682
status: test
description: |
    Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this could indicate a possible phishing attempt.
references:
    - https://app.any.run/tasks/69c5abaa-92ad-45ba-8c53-c11e23e05d04/ # PDF Document
    - https://app.any.run/tasks/64043a79-165f-4052-bcba-e6e49f847ec1/ # Office Document
author: Joseph Kamau
date: 2024-05-27
modified: 2025-10-07
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|contains:
            - 'Acrobat Reader'
            - 'Microsoft Office'
            - 'PDF Reader'
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\maxthon.exe'
            - '\seamonkey.exe'
            - '\vivaldi.exe'
        CommandLine|contains: 'http'
    filter_main_microsoft_help:
        CommandLine|contains: 'https://go.microsoft.com/fwlink/'
    filter_optional_foxit:
        CommandLine|contains:
            - 'http://ad.foxitsoftware.com/adlog.php?'
            - 'https://globe-map.foxitservice.com/go.php?do=redirect'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unlikely in most cases, further investigation should be done in the commandline of the browser process to determine the context of the URL accessed.
level: medium
```
