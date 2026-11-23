---
title: Vim GTFOBin Abuse - Linux
summary: |-
  Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
  Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
sigma_id: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
  - TA0007
techniques:
  - T1059
  - T1083
author: Nasreddine Bencherchali (Nextron Systems), Luc Génaux
date: '2022-12-28'
modified: '2026-06-05'
falsepositives:
  - Unknown
references:
  - https://gtfobins.github.io/gtfobins/vi/
  - https://gtfobins.github.io/gtfobins/vim/
  - https://gtfobins.github.io/gtfobins/rvim/
  - https://gtfobins.github.io/gtfobins/vimdiff/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_vim_shell_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Vim GTFOBin Abuse - Linux
id: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
status: test
description: |
    Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
    Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/vi/
    - https://gtfobins.github.io/gtfobins/vim/
    - https://gtfobins.github.io/gtfobins/rvim/
    - https://gtfobins.github.io/gtfobins/vimdiff/
author: Nasreddine Bencherchali (Nextron Systems), Luc Génaux
date: 2022-12-28
modified: 2026-06-05
tags:
    - attack.execution
    - attack.discovery
    - attack.t1059
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith:
            - '/rvim'
            - '/vi'
            - '/vim'
            - '/vimdiff'
        CommandLine|contains:
            - ' --cmd '
            - ' -c'
    selection_cli:
        CommandLine|contains:
            - ':!/'
            - ':!$'
            - ':!..'
            - ':lua '
            - ':py '
            - ':shell'
            - '/bin/bash'
            - '/bin/dash'
            - '/bin/fish'
            - '/bin/sh'
            - '/bin/csh'
            - '/bin/ksh'
            - '/bin/zsh'
            - '/bin/tmux'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
