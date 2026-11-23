---
title: Kernel Memory Dump Via LiveKD
summary: Detects execution of LiveKD with the "-m" flag to potentially dump the kernel memory
sigma_id: c7746f1c-47d3-43d6-8c45-cd1e54b6b0a2
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-16'
modified: '2024-03-13'
falsepositives:
  - Unlikely in production environment
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
  - https://4sysops.com/archives/creating-a-complete-memory-dump-without-a-blue-screen/
  - https://kb.acronis.com/content/60892
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_livekd_kernel_memory_dump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Kernel Memory Dump Via LiveKD
id: c7746f1c-47d3-43d6-8c45-cd1e54b6b0a2
status: test
description: Detects execution of LiveKD with the "-m" flag to potentially dump the kernel memory
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
    - https://4sysops.com/archives/creating-a-complete-memory-dump-without-a-blue-screen/
    - https://kb.acronis.com/content/60892
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-16
modified: 2024-03-13
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\livekd.exe'
              - '\livekd64.exe'
        - OriginalFileName: 'livekd.exe'
    selection_cli:
        CommandLine|contains|windash: ' -m'
    condition: all of selection_*
falsepositives:
    - Unlikely in production environment
level: high
```
