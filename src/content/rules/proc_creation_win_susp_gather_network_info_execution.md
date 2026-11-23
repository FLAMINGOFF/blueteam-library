---
title: Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS
summary: Detects execution of the built-in script located in "C:\Windows\System32\gatherNetworkInfo.vbs". Which can be used to gather information about the target machine
sigma_id: 07aa184a-870d-413d-893a-157f317f6f58
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
  - TA0002
techniques:
  - T1615
  - T1059.005
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-08'
falsepositives:
  - Unknown
references:
  - https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
  - https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_gather_network_info_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS
id: 07aa184a-870d-413d-893a-157f317f6f58
related:
    - id: f92a6f1e-a512-4a15-9735-da09e78d7273 # FileCreate
      type: similar
    - id: 575dce0c-8139-4e30-9295-1ee75969f7fe # ProcCreation LOLBIN
      type: similar
status: test
description: Detects execution of the built-in script located in "C:\Windows\System32\gatherNetworkInfo.vbs". Which can be used to gather information about the target machine
references:
    - https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
    - https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-08
tags:
    - attack.discovery
    - attack.execution
    - attack.t1615
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'gatherNetworkInfo.vbs'
    filter:
        Image|endswith:
            - '\cscript.exe'
            - '\wscript.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_susp_gather_network_info_execution/info.yml
```
