---
title: Remote Access Tool - Team Viewer Session Started On Linux Host
summary: |-
  Detects the command line executed when TeamViewer starts a session started by a remote host.
  Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.
sigma_id: 1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0003
  - TA0001
techniques:
  - T1133
author: Josh Nickels, Qi Nan
date: '2024-03-11'
falsepositives:
  - Legitimate usage of TeamViewer
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_remote_access_tools_teamviewer_incoming_connection.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - Team Viewer Session Started On Linux Host
id: 1f6b8cd4-3e60-47cc-b282-5aa1cbc9182d
related:
    - id: ab70c354-d9ac-4e11-bbb6-ec8e3b153357
      type: similar
    - id: f459ccb4-9805-41ea-b5b2-55e279e2424a
      type: similar
status: test
description: |
    Detects the command line executed when TeamViewer starts a session started by a remote host.
    Once a connection has been started, an investigator can verify the connection details by viewing the "incoming_connections.txt" log file in the TeamViewer folder.
references:
    - Internal Research
author: Josh Nickels, Qi Nan
date: 2024-03-11
tags:
    - attack.persistence
    - attack.initial-access
    - attack.t1133
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        ParentImage|endswith: '/TeamViewer_Service'
        Image|endswith: '/TeamViewer_Desktop'
        CommandLine|endswith: '/TeamViewer_Desktop --IPCport 5939 --Module 1'
    condition: selection
falsepositives:
    - Legitimate usage of TeamViewer
level: low
```
