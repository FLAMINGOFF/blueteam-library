---
title: Linux Network Service Scanning Tools Execution
summary: Detects execution of network scanning and reconnaissance tools. These tools can be used for the enumeration of local or remote network services for example.
sigma_id: 3e102cd9-a70d-4a7a-9508-403963092f31
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0007
techniques:
  - T1046
author: Alejandro Ortuno, oscd.community, Georg Lauenstein (sure[secure])
date: '2020-10-21'
modified: '2024-09-19'
falsepositives:
  - Legitimate administration activities
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
  - https://github.com/projectdiscovery/naabu
  - https://github.com/Tib3rius/AutoRecon
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_susp_network_utilities_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Network Service Scanning Tools Execution
id: 3e102cd9-a70d-4a7a-9508-403963092f31
status: test
description: Detects execution of network scanning and reconnaissance tools. These tools can be used for the enumeration of local or remote network services for example.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
    - https://github.com/projectdiscovery/naabu
    - https://github.com/Tib3rius/AutoRecon
author: Alejandro Ortuno, oscd.community, Georg Lauenstein (sure[secure])
date: 2020-10-21
modified: 2024-09-19
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: linux
detection:
    selection_netcat:
        Image|endswith:
            - '/nc'
            - '/ncat'
            - '/netcat'
            - '/socat'
    selection_network_scanning_tools:
        Image|endswith:
            - '/autorecon'
            - '/hping'
            - '/hping2'
            - '/hping3'
            - '/naabu'
            - '/nmap'
            - '/nping'
            - '/telnet' # could be wget, curl, ssh, many things. basically everything that is able to do network connection. consider fine tuning
            - '/zenmap'
    filter_main_netcat_listen_flag:
        CommandLine|contains:
            - ' --listen '
            - ' -l '
    condition: (selection_netcat and not filter_main_netcat_listen_flag) or selection_network_scanning_tools
falsepositives:
    - Legitimate administration activities
level: low
```
