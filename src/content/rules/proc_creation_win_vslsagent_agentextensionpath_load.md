---
title: Suspicious Vsls-Agent Command With AgentExtensionPath Load
summary: Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter
sigma_id: 43103702-5886-11ed-9b6a-0242ac120002
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: bohops
date: '2022-10-30'
falsepositives:
  - False positives depend on custom use of vsls-agent.exe
references:
  - https://twitter.com/bohops/status/1583916360404729857
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vslsagent_agentextensionpath_load.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Vsls-Agent Command With AgentExtensionPath Load
id: 43103702-5886-11ed-9b6a-0242ac120002
status: test
description: Detects Microsoft Visual Studio vsls-agent.exe lolbin execution with a suspicious library load using the --agentExtensionPath parameter
references:
    - https://twitter.com/bohops/status/1583916360404729857
author: bohops
date: 2022-10-30
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\vsls-agent.exe'
        CommandLine|contains: '--agentExtensionPath'
    filter:
        CommandLine|contains: 'Microsoft.VisualStudio.LiveShare.Agent.'
    condition: selection and not filter
falsepositives:
    - False positives depend on custom use of vsls-agent.exe
level: medium
```
