---
title: Remote Access Tool - Potential MeshAgent Execution - Windows
summary: |-
  Detects potential execution of MeshAgent which is a tool used for remote access.
  Historical data shows that threat actors rename MeshAgent binary to evade detection.
  Matching command lines with the '--meshServiceName' argument can indicate that the MeshAgent is being used for remote access.
sigma_id: 2fbbe9ff-0afc-470b-bdc0-592198339968
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Norbert Jaśniewicz (AlphaSOC)
date: '2025-05-19'
falsepositives:
  - Environments that legitimately use MeshAgent
references:
  - https://www.huntress.com/blog/know-thy-enemy-a-novel-november-case-on-persistent-remote-access
  - https://thecyberexpress.com/ukraine-hit-by-meshagent-malware-campaign/
  - https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/
  - https://www.security.com/threat-intelligence/medusa-ransomware-attacks
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_meshagent_arguments.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - Potential MeshAgent Execution - Windows
id: 2fbbe9ff-0afc-470b-bdc0-592198339968
related:
    - id: 22c45af6-f590-4d44-bab3-b5b2d2a2b6d9
      type: similar
status: experimental
description: |
    Detects potential execution of MeshAgent which is a tool used for remote access.
    Historical data shows that threat actors rename MeshAgent binary to evade detection.
    Matching command lines with the '--meshServiceName' argument can indicate that the MeshAgent is being used for remote access.
references:
    - https://www.huntress.com/blog/know-thy-enemy-a-novel-november-case-on-persistent-remote-access
    - https://thecyberexpress.com/ukraine-hit-by-meshagent-malware-campaign/
    - https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/
    - https://www.security.com/threat-intelligence/medusa-ransomware-attacks
author: Norbert Jaśniewicz (AlphaSOC)
date: 2025-05-19
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '--meshServiceName'
    condition: selection
falsepositives:
    - Environments that legitimately use MeshAgent
level: medium
```
