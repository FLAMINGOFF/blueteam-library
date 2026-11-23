---
title: WhoAmI as Parameter
summary: Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)
sigma_id: e9142d84-fbe0-401d-ac50-3e519fb00c89
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1033
author: Florian Roth (Nextron Systems)
date: '2021-11-29'
modified: '2022-12-25'
falsepositives:
  - Unknown
references:
  - https://twitter.com/blackarrowsec/status/1463805700602224645?s=12
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_whoami_as_param.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: WhoAmI as Parameter
id: e9142d84-fbe0-401d-ac50-3e519fb00c89
status: test
description: Detects a suspicious process command line that uses whoami as first parameter (as e.g. used by EfsPotato)
references:
    - https://twitter.com/blackarrowsec/status/1463805700602224645?s=12
author: Florian Roth (Nextron Systems)
date: 2021-11-29
modified: 2022-12-25
tags:
    - attack.discovery
    - attack.t1033
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '.exe whoami'
    condition: selection
falsepositives:
    - Unknown
level: high
```
