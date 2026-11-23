---
title: Suspicious ZipExec Execution
summary: ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.
sigma_id: 90dcf730-1b71-4ae7-9ffc-6fcf62bd0132
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
  - T1202
author: frack113
date: '2021-11-07'
modified: '2022-12-25'
falsepositives:
  - Unknown
references:
  - https://twitter.com/SBousseaden/status/1451237393017839616
  - https://github.com/Tylous/ZipExec
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_zipexec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious ZipExec Execution
id: 90dcf730-1b71-4ae7-9ffc-6fcf62bd0132
status: test
description: ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file.
references:
    - https://twitter.com/SBousseaden/status/1451237393017839616
    - https://github.com/Tylous/ZipExec
author: frack113
date: 2021-11-07
modified: 2022-12-25
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    run:
        CommandLine|contains|all:
            - '/generic:Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
            - '/pass:'
            - '/user:'
    delete:
        CommandLine|contains|all:
            - '/delete'
            - 'Microsoft_Windows_Shell_ZipFolder:filename='
            - '.zip'
    condition: run or delete
falsepositives:
    - Unknown
level: medium
```
