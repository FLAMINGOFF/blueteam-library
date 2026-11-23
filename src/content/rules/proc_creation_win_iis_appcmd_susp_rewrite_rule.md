---
title: Suspicious IIS URL GlobalRules Rewrite Via AppCmd
summary: Detects usage of "appcmd" to create new global URL rewrite rules. This behaviour has been observed being used by threat actors to add new rules so they can access their webshells.
sigma_id: 7c8af9b2-dcae-41a2-a9db-b28c288b5f08
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-22'
falsepositives:
  - Legitimate usage of appcmd to add new URL rewrite rules
references:
  - https://twitter.com/malmoeb/status/1616702107242971144
  - https://learn.microsoft.com/en-us/answers/questions/739120/how-to-add-re-write-global-rule-with-action-type-r
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_iis_appcmd_susp_rewrite_rule.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious IIS URL GlobalRules Rewrite Via AppCmd
id: 7c8af9b2-dcae-41a2-a9db-b28c288b5f08
status: test
description: Detects usage of "appcmd" to create new global URL rewrite rules. This behaviour has been observed being used by threat actors to add new rules so they can access their webshells.
references:
    - https://twitter.com/malmoeb/status/1616702107242971144
    - https://learn.microsoft.com/en-us/answers/questions/739120/how-to-add-re-write-global-rule-with-action-type-r
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-22
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\appcmd.exe'
        - OriginalFileName: 'appcmd.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'set'
            - 'config'
            - 'section:system.webServer/rewrite/globalRules'
            - 'commit:'
    condition: all of selection_*
falsepositives:
    - Legitimate usage of appcmd to add new URL rewrite rules
level: medium
```
