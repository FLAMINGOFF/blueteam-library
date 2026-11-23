---
title: Suspicious UltraVNC Execution
summary: Detects suspicious UltraVNC command line flag combination that indicate a auto reconnect upon execution, e.g. startup (as seen being used by Gamaredon threat group)
sigma_id: 871b9555-69ca-4993-99d3-35a59f9f3599
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021.005
author: Bhabesh Raj
date: '2022-03-04'
modified: '2022-03-09'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20220224045756/https://www.ria.ee/sites/default/files/content-editors/kuberturve/tale_of_gamaredon_infection.pdf
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-gamaredon-espionage-ukraine
  - https://unit42.paloaltonetworks.com/unit-42-title-gamaredon-group-toolset-evolution
  - https://web.archive.org/web/20240528223522/https://uvnc.com/docs/uvnc-viewer/52-ultravnc-viewer-commandline-parameters.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ultravnc_susp_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious UltraVNC Execution
id: 871b9555-69ca-4993-99d3-35a59f9f3599
status: test
description: Detects suspicious UltraVNC command line flag combination that indicate a auto reconnect upon execution, e.g. startup (as seen being used by Gamaredon threat group)
references:
    - https://web.archive.org/web/20220224045756/https://www.ria.ee/sites/default/files/content-editors/kuberturve/tale_of_gamaredon_infection.pdf
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-gamaredon-espionage-ukraine
    - https://unit42.paloaltonetworks.com/unit-42-title-gamaredon-group-toolset-evolution
    - https://web.archive.org/web/20240528223522/https://uvnc.com/docs/uvnc-viewer/52-ultravnc-viewer-commandline-parameters.html
author: Bhabesh Raj
date: 2022-03-04
modified: 2022-03-09
tags:
    - attack.lateral-movement
    - attack.g0047
    - attack.t1021.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-autoreconnect '
            - '-connect '
            - '-id:'
    condition: selection
falsepositives:
    - Unknown
level: high
```
