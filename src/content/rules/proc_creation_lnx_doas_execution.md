---
title: Linux Doas Tool Execution
summary: Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.
sigma_id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0004
techniques:
  - T1548
author: Sittikorn S, Teoderick Contreras
date: '2022-01-20'
falsepositives:
  - Unlikely
references:
  - https://research.splunk.com/endpoint/d5a62490-6e09-11ec-884e-acde48001122/
  - https://www.makeuseof.com/how-to-install-and-use-doas/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_doas_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Doas Tool Execution
id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
description: Detects the doas tool execution in linux host platform. This utility tool allow standard users to perform tasks as root, the same way sudo does.
references:
    - https://research.splunk.com/endpoint/d5a62490-6e09-11ec-884e-acde48001122/
    - https://www.makeuseof.com/how-to-install-and-use-doas/
author: Sittikorn S, Teoderick Contreras
date: 2022-01-20
tags:
    - attack.privilege-escalation
    - attack.t1548
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/doas'
    condition: selection
falsepositives:
    - Unlikely
level: low
```
