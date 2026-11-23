---
title: Suspicious SysAidServer Child
summary: Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)
sigma_id: 60bfeac3-0d35-4302-8efb-1dd16f715bc6
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1210
author: Florian Roth (Nextron Systems)
date: '2022-08-26'
falsepositives:
  - Unknown
references:
  - https://www.microsoft.com/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_java_sysaidserver_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious SysAidServer Child
id: 60bfeac3-0d35-4302-8efb-1dd16f715bc6
status: test
description: Detects suspicious child processes of SysAidServer (as seen in MERCURY threat actor intrusions)
references:
    - https://www.microsoft.com/security/blog/2022/08/25/mercury-leveraging-log4j-2-vulnerabilities-in-unpatched-systems-to-target-israeli-organizations/
author: Florian Roth (Nextron Systems)
date: 2022-08-26
tags:
    - attack.lateral-movement
    - attack.t1210
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\java.exe'
            - '\javaw.exe'
        ParentCommandLine|contains: 'SysAidServer'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
