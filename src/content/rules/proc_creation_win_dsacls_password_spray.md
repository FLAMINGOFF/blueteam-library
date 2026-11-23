---
title: Potential Password Spraying Attempt Using Dsacls.EXE
summary: Detects possible password spraying attempts using Dsacls
sigma_id: bac9fb54-2da7-44e9-988f-11e9a5edbc0c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-20'
modified: '2023-02-04'
falsepositives:
  - Legitimate use of dsacls to bind to an LDAP session
references:
  - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions#password-spraying-anyone
  - https://ss64.com/nt/dsacls.html
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151(v=ws.11)
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_dsacls_password_spray.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Password Spraying Attempt Using Dsacls.EXE
id: bac9fb54-2da7-44e9-988f-11e9a5edbc0c
status: test
description: Detects possible password spraying attempts using Dsacls
references:
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions#password-spraying-anyone
    - https://ss64.com/nt/dsacls.html
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151(v=ws.11)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-20
modified: 2023-02-04
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\dsacls.exe'
        - OriginalFileName: "DSACLS.EXE"
    selection_cli:
        CommandLine|contains|all:
            - '/user:'
            - '/passwd:'
    condition: all of selection*
falsepositives:
    - Legitimate use of dsacls to bind to an LDAP session
level: medium
```
