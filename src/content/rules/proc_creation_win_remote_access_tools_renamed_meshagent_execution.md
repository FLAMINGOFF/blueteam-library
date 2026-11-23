---
title: Remote Access Tool - Renamed MeshAgent Execution - Windows
summary: |-
  Detects the execution of a renamed instance of the Remote Monitoring and Management (RMM) tool, MeshAgent.
  RMM tools such as MeshAgent are commonly utilized by IT administrators for legitimate remote support and system management.
  However, malicious actors may exploit these tools by renaming them to bypass detection mechanisms, enabling unauthorized access and control over compromised systems.
sigma_id: b471f462-eb0d-4832-be35-28d94bdb4780
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
  - TA0005
techniques:
  - T1219.002
  - T1036.003
author: Norbert Jaśniewicz (AlphaSOC)
date: '2025-05-19'
falsepositives:
  - Unknown
references:
  - https://www.huntress.com/blog/know-thy-enemy-a-novel-november-case-on-persistent-remote-access
  - https://thecyberexpress.com/ukraine-hit-by-meshagent-malware-campaign/
  - https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/
  - https://www.security.com/threat-intelligence/medusa-ransomware-attacks
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_renamed_meshagent_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - Renamed MeshAgent Execution - Windows
id: b471f462-eb0d-4832-be35-28d94bdb4780
related:
    - id: bd3b5eaa-439d-4a42-8f35-a49f5c8a2582
      type: similar
    - id: 2fbbe9ff-0afc-470b-bdc0-592198339968
      type: derived
status: experimental
description: |
    Detects the execution of a renamed instance of the Remote Monitoring and Management (RMM) tool, MeshAgent.
    RMM tools such as MeshAgent are commonly utilized by IT administrators for legitimate remote support and system management.
    However, malicious actors may exploit these tools by renaming them to bypass detection mechanisms, enabling unauthorized access and control over compromised systems.
references:
    - https://www.huntress.com/blog/know-thy-enemy-a-novel-november-case-on-persistent-remote-access
    - https://thecyberexpress.com/ukraine-hit-by-meshagent-malware-campaign/
    - https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/
    - https://www.security.com/threat-intelligence/medusa-ransomware-attacks
author: Norbert Jaśniewicz (AlphaSOC)
date: 2025-05-19
tags:
    - attack.command-and-control
    - attack.stealth
    - attack.t1219.002
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_meshagent:
        - CommandLine|contains: '--meshServiceName'
        - OriginalFileName|contains: 'meshagent'
    filter_main_legitimate:
        Image|endswith: '\meshagent.exe'
    condition: selection_meshagent and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
