---
title: Potential NTLM Coercion Via Certutil.EXE
summary: Detects possible NTLM coercion via certutil using the 'syncwithWU' flag
sigma_id: 6c6d9280-e6d0-4b9d-80ac-254701b64916
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-01'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://github.com/LOLBAS-Project/LOLBAS/issues/243
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_certutil_ntlm_coercion.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential NTLM Coercion Via Certutil.EXE
id: 6c6d9280-e6d0-4b9d-80ac-254701b64916
status: test
description: Detects possible NTLM coercion via certutil using the 'syncwithWU' flag
references:
    - https://github.com/LOLBAS-Project/LOLBAS/issues/243
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-01
modified: 2023-02-14
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' -syncwithWU '
            - ' \\\\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_certutil_ntlm_coercion/info.yml
```
