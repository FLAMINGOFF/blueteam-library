---
title: HackTool - HandleKatz Duplicating LSASS Handle
summary: Detects HandleKatz opening LSASS to duplicate its handle to later dump the memory without opening any new handles
sigma_id: b1bd3a59-c1fd-4860-9f40-4dd161a7d1f5
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0002
  - TA0006
techniques:
  - T1106
  - T1003.001
author: Bhabesh Raj (rule), @thefLinkk
date: '2022-06-27'
modified: '2023-11-28'
falsepositives:
  - Unknown
references:
  - https://github.com/codewhitesec/HandleKatz
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_hktl_handlekatz_lsass_access.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - HandleKatz Duplicating LSASS Handle
id: b1bd3a59-c1fd-4860-9f40-4dd161a7d1f5
status: test
description: Detects HandleKatz opening LSASS to duplicate its handle to later dump the memory without opening any new handles
references:
    - https://github.com/codewhitesec/HandleKatz
author: Bhabesh Raj (rule), @thefLinkk
date: 2022-06-27
modified: 2023-11-28
tags:
    - attack.execution
    - attack.t1106
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe' # Theoretically, can be any benign process holding handle to LSASS
        GrantedAccess: '0x1440' # Only PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_QUERY_INFORMATION
        # Example: C:\Windows\SYSTEM32\ntdll.dll+9d234\|UNKNOWN(00000000001C119B)
        CallTrace|startswith: 'C:\Windows\System32\ntdll.dll+'
        CallTrace|contains: '|UNKNOWN('
        CallTrace|endswith: ')'
    condition: selection
falsepositives:
    - Unknown
level: high
```
