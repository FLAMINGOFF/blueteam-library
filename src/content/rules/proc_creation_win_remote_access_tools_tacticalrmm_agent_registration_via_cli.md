---
title: Remote Access Tool - TacticalRMM Agent Registration to Potentially Attacker-Controlled Server
summary: |-
  Detects TacticalRMM agent installations where the --api, --auth, and related flags are used on the command line.
  These parameters configure the agent to connect to a specific RMM server with authentication, client ID, and site ID.
  This technique could indicate a threat actor attempting to register the agent with an attacker-controlled RMM infrastructure silently.
sigma_id: 2db93a3f-3249-4f73-9e68-0e77a0f8ae7e
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219
  - T1105
author: Ahmed Nosir (@egycondor)
date: '2025-05-29'
falsepositives:
  - Legitimate system administrator deploying TacticalRMM
references:
  - https://github.com/amidaware/tacticalrmm
  - https://apophis133.medium.com/powershell-script-tactical-rmm-installation-45afb639eff3
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_tacticalrmm_agent_registration_via_cli.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - TacticalRMM Agent Registration to Potentially Attacker-Controlled Server
id: 2db93a3f-3249-4f73-9e68-0e77a0f8ae7e
status: experimental
description: |
    Detects TacticalRMM agent installations where the --api, --auth, and related flags are used on the command line.
    These parameters configure the agent to connect to a specific RMM server with authentication, client ID, and site ID.
    This technique could indicate a threat actor attempting to register the agent with an attacker-controlled RMM infrastructure silently.
references:
    - https://github.com/amidaware/tacticalrmm
    - https://apophis133.medium.com/powershell-script-tactical-rmm-installation-45afb639eff3
author: Ahmed Nosir (@egycondor)
date: 2025-05-29
tags:
    - attack.command-and-control
    - attack.t1219
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '\TacticalAgent\tacticalrmm.exe'
        CommandLine|contains|all:
            - '--api'
            - '--auth'
            - '--client-id'
            - '--site-id'
            - '--agent-type'
    condition: selection
falsepositives:
    - Legitimate system administrator deploying TacticalRMM
level: medium
```
