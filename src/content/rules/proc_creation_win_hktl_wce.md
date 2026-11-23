---
title: HackTool - Windows Credential Editor (WCE) Execution
summary: |-
  Detects the use of Windows Credential Editor (WCE), a popular post-exploitation tool used to extract plaintext passwords, hash, PIN code and Kerberos tickets from memory.
  It is often used by threat actors for credential dumping and lateral movement within compromised networks.
sigma_id: 7aa7009a-28b9-4344-8c1f-159489a390df
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2019-12-31'
modified: '2025-10-21'
falsepositives:
  - Unknown
references:
  - https://www.ampliasecurity.com/research/windows-credentials-editor/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_wce.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Windows Credential Editor (WCE) Execution
id: 7aa7009a-28b9-4344-8c1f-159489a390df
status: test
description: |
    Detects the use of Windows Credential Editor (WCE), a popular post-exploitation tool used to extract plaintext passwords, hash, PIN code and Kerberos tickets from memory.
    It is often used by threat actors for credential dumping and lateral movement within compromised networks.
references:
    - https://www.ampliasecurity.com/research/windows-credentials-editor/
author: Florian Roth (Nextron Systems)
date: 2019-12-31
modified: 2025-10-21
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.s0005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\WCE.exe'
            - '\WCE64.exe'
    selection_hash:
        Hashes|contains:
            - 'IMPHASH=136F0A8572C058A96436C82E541E4C41'
            - 'IMPHASH=589657C64DDE88533186C39F82FA1F50'
            - 'IMPHASH=6BFE09EFCB4FFDE061EBDBAFC4DB84CF'
            - 'IMPHASH=7D490037BF450877E6D0287BDCFF8D2E'
            - 'IMPHASH=8AB93B061287C79F3088C5BC7E7D97ED'
            - 'IMPHASH=A53A02B997935FD8EEDCB5F7ABAB9B9F'
            - 'IMPHASH=BA434A7A729EEC20E136CA4C32D6C740'
            - 'IMPHASH=BD1D1547DA13C0FCB6C15E86217D5EB8'
            - 'IMPHASH=E96A73C7BF33A464C510EDE582318BF2'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: critical
```
