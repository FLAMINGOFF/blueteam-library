---
title: HackTool - CreateMiniDump Execution
summary: Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine
sigma_id: 36d88494-1d43-4dc0-b3fa-35c8fea0ca9d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2019-12-22'
modified: '2024-11-23'
falsepositives:
  - Unknown
references:
  - https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_createminidump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - CreateMiniDump Execution
id: 36d88494-1d43-4dc0-b3fa-35c8fea0ca9d
status: test
description: Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine
references:
    - https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
author: Florian Roth (Nextron Systems)
date: 2019-12-22
modified: 2024-11-23
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\CreateMiniDump.exe'
        - Hashes|contains: 'IMPHASH=4a07f944a83e8a7c2525efa35dd30e2f'
    condition: selection
falsepositives:
    - Unknown
level: high
```
