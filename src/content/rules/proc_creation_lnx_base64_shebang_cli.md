---
title: Linux Base64 Encoded Shebang In CLI
summary: Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded
sigma_id: fe2f9663-41cb-47e2-b954-8a228f3b9dff
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0005
techniques:
  - T1140
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-15'
falsepositives:
  - Legitimate administration activities
references:
  - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
  - https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Base64 Encoded Shebang In CLI
id: fe2f9663-41cb-47e2-b954-8a228f3b9dff
status: test
description: Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded
references:
    - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
    - https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.stealth
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - "IyEvYmluL2Jhc2" # Note: #!/bin/bash"
            - "IyEvYmluL2Rhc2" # Note: #!/bin/dash"
            - "IyEvYmluL3pza" # Note: #!/bin/zsh"
            - "IyEvYmluL2Zpc2" # Note: #!/bin/fish
            - "IyEvYmluL3No" # Note: # !/bin/sh"
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
