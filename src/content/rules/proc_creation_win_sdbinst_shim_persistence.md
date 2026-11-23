---
title: Potential Shim Database Persistence via Sdbinst.EXE
summary: |-
  Detects installation of a new shim using sdbinst.exe.
  Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
sigma_id: 517490a7-115a-48c6-8862-1a481504d5a8
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0004
techniques:
  - T1546.011
author: Markus Neis
date: '2019-01-16'
modified: '2023-12-06'
falsepositives:
  - Unknown
references:
  - https://www.mandiant.com/resources/blog/fin7-shim-databases-persistence
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Shim Database Persistence via Sdbinst.EXE
id: 517490a7-115a-48c6-8862-1a481504d5a8
related:
    - id: 18ee686c-38a3-4f65-9f44-48a077141f42
      type: similar
status: test
description: |
    Detects installation of a new shim using sdbinst.exe.
    Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims
references:
    - https://www.mandiant.com/resources/blog/fin7-shim-databases-persistence
author: Markus Neis
date: 2019-01-16
modified: 2023-12-06
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1546.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\sdbinst.exe'
        - OriginalFileName: 'sdbinst.exe'
    selection_cli:
        CommandLine|contains: '.sdb'
    filter_optional_iis:
        ParentImage|endswith: '\msiexec.exe'
        CommandLine|contains:
            # Expected behavior for IIS Express (e.g. https://www.hybrid-analysis.com/sample/15d4ff941f77f7bdfc9dfb2399b7b952a0a2c860976ef3e835998ff4796e5e91?environmentId=120)
            - ':\Program Files (x86)\IIS Express\iisexpressshim.sdb'
            - ':\Program Files\IIS Express\iisexpressshim.sdb'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_sdbinst_shim_persistence/info.yml
```
