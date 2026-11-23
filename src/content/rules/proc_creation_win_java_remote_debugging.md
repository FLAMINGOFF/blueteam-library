---
title: Java Running with Remote Debugging
summary: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
sigma_id: 8f88e3f6-2a49-48f5-a5c4-2f7eedf78710
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1203
author: Florian Roth (Nextron Systems)
date: '2019-01-16'
modified: '2023-02-01'
falsepositives:
  - Unknown
references:
  - https://dzone.com/articles/remote-debugging-java-applications-with-jdwp
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_java_remote_debugging.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Java Running with Remote Debugging
id: 8f88e3f6-2a49-48f5-a5c4-2f7eedf78710
status: test
description: Detects a JAVA process running with remote debugging allowing more than just localhost to connect
references:
    - https://dzone.com/articles/remote-debugging-java-applications-with-jdwp
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2023-02-01
tags:
    - attack.t1203
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_jdwp_transport:
        CommandLine|contains: 'transport=dt_socket,address='
    selection_old_jvm_version:
        CommandLine|contains:
            - 'jre1.'
            - 'jdk1.'
    exclusion:
        CommandLine|contains:
            - 'address=127.0.0.1'
            - 'address=localhost'
    condition: all of selection_* and not exclusion
falsepositives:
    - Unknown
level: medium
```
