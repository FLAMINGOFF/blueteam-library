---
title: Visual Studio Code Tunnel Execution
summary: Detects Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
sigma_id: 90d6bd71-dffb-4989-8d86-a827fedd6624
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1071.001
  - T1219
author: Nasreddine Bencherchali (Nextron Systems), citron_ninja
date: '2023-10-25'
modified: '2025-10-29'
falsepositives:
  - Legitimate use of Visual Studio Code tunnel
references:
  - https://ipfyx.fr/post/visual-studio-code-tunnel/
  - https://badoption.eu/blog/2023/01/31/code_c2.html
  - https://code.visualstudio.com/docs/remote/tunnels
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vscode_tunnel_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Visual Studio Code Tunnel Execution
id: 90d6bd71-dffb-4989-8d86-a827fedd6624
status: test
description: Detects Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
    - https://code.visualstudio.com/docs/remote/tunnels
author: Nasreddine Bencherchali (Nextron Systems), citron_ninja
date: 2023-10-25
modified: 2025-10-29
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_only_tunnel:
        OriginalFileName: null
        CommandLine|endswith: '.exe tunnel'
    selection_tunnel_args:
        CommandLine|contains|all:
            - '.exe tunnel'
            - '--accept-server-license-terms'
    selection_parent_tunnel:
        ParentCommandLine|endswith: ' tunnel'
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - '/d /c '
            - '\servers\Stable-'
            - 'code-server.cmd'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Visual Studio Code tunnel
level: medium
```
