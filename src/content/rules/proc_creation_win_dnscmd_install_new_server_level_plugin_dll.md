---
title: New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE
summary: Detects the installation of a DNS plugin DLL via ServerLevelPluginDll parameter in registry, which can be used to execute code in context of the DNS server (restart required)
sigma_id: f63b56ee-3f79-4b8a-97fb-5c48007e8573
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1574.001
  - T1112
author: Florian Roth (Nextron Systems)
date: '2017-05-08'
modified: '2023-02-05'
falsepositives:
  - Unknown
references:
  - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
  - https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_dnscmd_install_new_server_level_plugin_dll.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE
id: f63b56ee-3f79-4b8a-97fb-5c48007e8573
related:
    - id: e61e8a88-59a9-451c-874e-70fcc9740d67
      type: derived
    - id: cbe51394-cd93-4473-b555-edf0144952d9
      type: derived
status: test
description: Detects the installation of a DNS plugin DLL via ServerLevelPluginDll parameter in registry, which can be used to execute code in context of the DNS server (restart required)
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
    - https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html
author: Florian Roth (Nextron Systems)
date: 2017-05-08
modified: 2023-02-05
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.defense-impairment
    - attack.t1574.001
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dnscmd.exe'
        CommandLine|contains|all:
            - '/config'
            - '/serverlevelplugindll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
