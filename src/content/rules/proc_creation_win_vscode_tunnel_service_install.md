---
title: Visual Studio Code Tunnel Service Installation
summary: Detects the installation of VsCode tunnel (code-tunnel) as a service.
sigma_id: 30bf1789-379d-4fdc-900f-55cd0a90a801
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1071.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-10-25'
falsepositives:
  - Legitimate installation of code-tunnel as a service
references:
  - https://ipfyx.fr/post/visual-studio-code-tunnel/
  - https://badoption.eu/blog/2023/01/31/code_c2.html
  - https://code.visualstudio.com/docs/remote/tunnels
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_vscode_tunnel_service_install.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Visual Studio Code Tunnel Service Installation
id: 30bf1789-379d-4fdc-900f-55cd0a90a801
status: test
description: Detects the installation of VsCode tunnel (code-tunnel) as a service.
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
    - https://code.visualstudio.com/docs/remote/tunnels
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-25
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'tunnel '
            - 'service'
            - 'internal-run'
            - 'tunnel-service.log'
    condition: selection
falsepositives:
    - Legitimate installation of code-tunnel as a service
level: medium
```
