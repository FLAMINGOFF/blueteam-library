---
title: Notepad Password Files Discovery
summary: Detects the execution of Notepad to open a file that has the string "password" which may indicate unauthorized access to credentials or suspicious activity.
sigma_id: 3b4e950b-a3ea-44d3-877e-432071990709
status: experimental
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1083
author: The DFIR Report
date: '2025-02-21'
falsepositives:
  - >-
    Legitimate use of opening files from remote hosts by administrators or users. However, storing passwords in text readable format could potentially be a violation of the organization's policy. Any
    match should be investigated further.
references:
  - https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/
  - https://intel.thedfirreport.com/eventReports/view/57
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_notepad_local_passwd_discovery.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Notepad Password Files Discovery
id: 3b4e950b-a3ea-44d3-877e-432071990709
status: experimental
description: Detects the execution of Notepad to open a file that has the string "password" which may indicate unauthorized access to credentials or suspicious activity.
references:
    - https://thedfirreport.com/2025/02/24/confluence-exploit-leads-to-lockbit-ransomware/
    - https://intel.thedfirreport.com/eventReports/view/57  # Private Report
author: 'The DFIR Report'
tags:
    - attack.discovery
    - attack.t1083
date: 2025-02-21
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\explorer.exe'
        Image|endswith: '\notepad.exe'
        CommandLine|endswith:
        # Note: Commandline to contain a file with the string password and a specific extension
            - 'password*.txt'
            - 'password*.csv'
            - 'password*.doc'
            - 'password*.xls'
    condition: selection
falsepositives:
    - Legitimate use of opening files from remote hosts by administrators or users. However, storing passwords in text readable format could potentially be a violation of the organization's policy. Any match should be investigated further.
level: low
```
