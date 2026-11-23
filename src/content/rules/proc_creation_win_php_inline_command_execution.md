---
title: Php Inline Command Execution
summary: Detects execution of php using the "-r" flag. This is could be used as a way to launch a reverse shell or execute live php code.
sigma_id: d81871ef-5738-47ab-9797-7a9c90cd4bfb
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-02'
falsepositives:
  - Unknown
references:
  - https://www.php.net/manual/en/features.commandline.php
  - https://www.revshells.com/
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_php_inline_command_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Php Inline Command Execution
id: d81871ef-5738-47ab-9797-7a9c90cd4bfb
status: test
description: Detects execution of php using the "-r" flag. This is could be used as a way to launch a reverse shell or execute live php code.
references:
    - https://www.php.net/manual/en/features.commandline.php
    - https://www.revshells.com/
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\php.exe'
        - OriginalFileName: 'php.exe'
    selection_cli:
        CommandLine|contains: ' -r'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
