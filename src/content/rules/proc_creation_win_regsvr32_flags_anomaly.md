---
title: Potential Regsvr32 Commandline Flag Anomaly
summary: Detects a potential command line flag anomaly related to "regsvr32" in which the "/i" flag is used without the "/n" which should be uncommon.
sigma_id: b236190c-1c61-41e9-84b3-3fe03f6d76b0
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.010
author: Florian Roth (Nextron Systems)
date: '2019-07-13'
modified: '2024-03-13'
falsepositives:
  - Administrator typo might cause some false positives
references:
  - https://twitter.com/sbousseaden/status/1282441816986484737?s=12
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regsvr32_flags_anomaly.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Regsvr32 Commandline Flag Anomaly
id: b236190c-1c61-41e9-84b3-3fe03f6d76b0
status: test
description: Detects a potential command line flag anomaly related to "regsvr32" in which the "/i" flag is used without the "/n" which should be uncommon.
references:
    - https://twitter.com/sbousseaden/status/1282441816986484737?s=12
author: Florian Roth (Nextron Systems)
date: 2019-07-13
modified: 2024-03-13
tags:
    - attack.stealth
    - attack.t1218.010
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|windash: ' -i:'
    filter_main_flag:
        CommandLine|contains|windash: ' -n '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrator typo might cause some false positives
level: medium
```
