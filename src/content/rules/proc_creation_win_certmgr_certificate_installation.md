---
title: New Root Certificate Installed Via CertMgr.EXE
summary: |-
  Detects execution of "certmgr" with the "add" flag in order to install a new certificate on the system.
  Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
sigma_id: ff992eac-6449-4c60-8c1d-91c9722a1d48
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1553.004
author: oscd.community, @redcanary, Zach Stanford @svch0st
date: '2023-03-05'
falsepositives:
  - Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md
  - https://securelist.com/to-crypt-or-to-mine-that-is-the-question/86307/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_certmgr_certificate_installation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New Root Certificate Installed Via CertMgr.EXE
id: ff992eac-6449-4c60-8c1d-91c9722a1d48
related:
    - id: 42821614-9264-4761-acfc-5772c3286f76
      type: derived
    - id: 46591fae-7a4c-46ea-aec3-dff5e6d785dc
      type: obsolete
status: test
description: |
    Detects execution of "certmgr" with the "add" flag in order to install a new certificate on the system.
    Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md
    - https://securelist.com/to-crypt-or-to-mine-that-is-the-question/86307/
author: oscd.community, @redcanary, Zach Stanford @svch0st
date: 2023-03-05
tags:
    - attack.defense-impairment
    - attack.t1553.004
logsource:
    category: process_creation
    product: windows
detection:
    # Example: CertMgr.exe /add CertificateFileName.cer /s /r localMachine root /all
    selection_img:
        - Image|endswith: '\CertMgr.exe'
        - OriginalFileName: 'CERTMGT.EXE'
    selection_cli:
        CommandLine|contains|all:
            - '/add'
            - 'root'
    condition: all of selection_*
falsepositives:
    - Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP
level: medium
```
