---
title: Suspicious LSASS Access Via MalSecLogon
summary: Detects suspicious access to LSASS handle via a call trace to "seclogon.dll" with a suspicious access right.
sigma_id: 472159c5-31b9-4f56-b794-b766faa8b0a7
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0006
techniques:
  - T1003.001
author: Samir Bousseaden (original elastic rule), Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-29'
falsepositives:
  - Unknown
references:
  - https://twitter.com/SBousseaden/status/1541920424635912196
  - https://github.com/elastic/detection-rules/blob/2bc1795f3d7bcc3946452eb4f07ae799a756d94e/rules/windows/credential_access_lsass_handle_via_malseclogon.toml
  - https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_lsass_seclogon_access.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious LSASS Access Via MalSecLogon
id: 472159c5-31b9-4f56-b794-b766faa8b0a7
status: test
description: Detects suspicious access to LSASS handle via a call trace to "seclogon.dll" with a suspicious access right.
references:
    - https://twitter.com/SBousseaden/status/1541920424635912196
    - https://github.com/elastic/detection-rules/blob/2bc1795f3d7bcc3946452eb4f07ae799a756d94e/rules/windows/credential_access_lsass_handle_via_malseclogon.toml
    - https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html
author: Samir Bousseaden (original elastic rule), Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-29
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage|endswith: '\svchost.exe'
        GrantedAccess: '0x14c0'
        CallTrace|contains: 'seclogon.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
