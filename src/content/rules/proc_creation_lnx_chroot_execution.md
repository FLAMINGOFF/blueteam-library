---
title: Linux Sudo Chroot Execution
summary: |-
  Detects the execution of 'sudo' command with '--chroot' option, which is used to change the root directory for command execution.
  Attackers may use this technique to evade detection and execute commands in a modified environment.
  This can be part of a privilege escalation strategy, as it allows the execution of commands with elevated privileges in a controlled environment as seen in CVE-2025-32463.
  While investigating, look out for unusual or unexpected use of 'sudo --chroot' in conjunction with other commands or scripts such as execution from temporary directories or unusual user accounts.
sigma_id: f2bed782-994e-4f40-9cd5-518198cb3fba
status: experimental
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0004
techniques:
  - T1068
author: Swachchhanda Shrawn Poudel (Nextron Systems)
date: '2025-10-02'
falsepositives:
  - Legitimate administrative tasks or scripts that use 'sudo --chroot' for containerization, testing, or system management.
references:
  - https://github.com/kh4sh3i/CVE-2025-32463/blob/81bb430f84fa2089224733c3ed4bfa434c197ad4/exploit.sh
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_chroot_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Linux Sudo Chroot Execution
id: f2bed782-994e-4f40-9cd5-518198cb3fba
status: experimental
description: |
    Detects the execution of 'sudo' command with '--chroot' option, which is used to change the root directory for command execution.
    Attackers may use this technique to evade detection and execute commands in a modified environment.
    This can be part of a privilege escalation strategy, as it allows the execution of commands with elevated privileges in a controlled environment as seen in CVE-2025-32463.
    While investigating, look out for unusual or unexpected use of 'sudo --chroot' in conjunction with other commands or scripts such as execution from temporary directories or unusual user accounts.
references:
    - https://github.com/kh4sh3i/CVE-2025-32463/blob/81bb430f84fa2089224733c3ed4bfa434c197ad4/exploit.sh
author: Swachchhanda Shrawn Poudel (Nextron Systems)
date: 2025-10-02
tags:
    - attack.privilege-escalation
    - attack.t1068
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/sudo'
        CommandLine|contains:
            - ' --chroot '
            - 'sudo -R '
    condition: selection
falsepositives:
    - Legitimate administrative tasks or scripts that use 'sudo --chroot' for containerization, testing, or system management.
level: low
```
