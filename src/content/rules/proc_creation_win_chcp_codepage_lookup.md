---
title: Console CodePage Lookup Via CHCP
summary: Detects use of chcp to look up the system locale value as part of host discovery
sigma_id: 7090adee-82e2-4269-bd59-80691e7c6338
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1614.001
author: _pete_0, TheDFIRReport
date: '2022-02-21'
modified: '2024-03-05'
falsepositives:
  - During Anaconda update the 'conda.exe' process will eventually execution the 'chcp' command.
  - Discord was seen using chcp to look up code pages
references:
  - https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chcp
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_chcp_codepage_lookup.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Console CodePage Lookup Via CHCP
id: 7090adee-82e2-4269-bd59-80691e7c6338
status: test
description: Detects use of chcp to look up the system locale value as part of host discovery
references:
    - https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chcp
author: _pete_0, TheDFIRReport
date: 2022-02-21
modified: 2024-03-05
tags:
    - attack.discovery
    - attack.t1614.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmd.exe'
        ParentCommandLine|contains|windash:
            - ' -c '
            - ' -r '
            - ' -k '
        Image|endswith: '\chcp.com'
        CommandLine|endswith:
            - 'chcp'
            - 'chcp '
            - 'chcp  '
    condition: selection
falsepositives:
    - During Anaconda update the 'conda.exe' process will eventually execution the 'chcp' command.
    - Discord was seen using chcp to look up code pages
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_chcp_codepage_lookup/info.yml
```
