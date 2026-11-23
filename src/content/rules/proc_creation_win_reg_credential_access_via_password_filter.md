---
title: Dropping Of Password Filter DLL
summary: Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS
sigma_id: b7966f4a-b333-455b-8370-8ca53c229762
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0006
  - TA0112
techniques:
  - T1556.002
author: Sreeman
date: '2020-10-29'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/
  - https://github.com/3gstudent/PasswordFilter/tree/master/PasswordFilter
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_credential_access_via_password_filter.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Dropping Of Password Filter DLL
id: b7966f4a-b333-455b-8370-8ca53c229762
status: test
description: Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS
references:
    - https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/
    - https://github.com/3gstudent/PasswordFilter/tree/master/PasswordFilter
author: Sreeman
date: 2020-10-29
modified: 2022-10-09
tags:
    - attack.persistence
    - attack.credential-access
    - attack.defense-impairment
    - attack.t1556.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdline:
        CommandLine|contains|all:
            - 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
            - 'scecli\0*'
            - 'reg add'
    condition: selection_cmdline
falsepositives:
    - Unknown
level: medium
```
