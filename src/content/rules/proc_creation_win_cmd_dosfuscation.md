---
title: Potential Dosfuscation Activity
summary: Detects possible payload obfuscation via the commandline
sigma_id: a77c1610-fc73-4019-8e29-0f51efc04a51
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: '2022-02-15'
modified: '2023-03-06'
falsepositives:
  - Unknown
references:
  - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf
  - https://github.com/danielbohannon/Invoke-DOSfuscation
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cmd_dosfuscation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Dosfuscation Activity
id: a77c1610-fc73-4019-8e29-0f51efc04a51
status: test
description: Detects possible payload obfuscation via the commandline
references:
    - https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf
    - https://github.com/danielbohannon/Invoke-DOSfuscation
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022-02-15
modified: 2023-03-06
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '^^'
            - '^|^'
            - ',;,'
            - ';;;;'
            - ';; ;;'
            - '(,(,'
            - '%COMSPEC:~'
            - ' c^m^d'
            - '^c^m^d'
            - ' c^md'
            - ' cm^d'
            - '^cm^d'
            - ' s^et '
            - ' s^e^t '
            - ' se^t '
            # - '%%'
            # - '&&'
            # - '""'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
