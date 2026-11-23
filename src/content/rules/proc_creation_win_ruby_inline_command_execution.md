---
title: Ruby Inline Command Execution
summary: Detects execution of ruby using the "-e" flag. This is could be used as a way to launch a reverse shell or execute live ruby code.
sigma_id: 20a5ffa1-3848-4584-b6f8-c7c7fd9f69c8
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
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  - https://www.revshells.com/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ruby_inline_command_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Ruby Inline Command Execution
id: 20a5ffa1-3848-4584-b6f8-c7c7fd9f69c8
status: test
description: Detects execution of ruby using the "-e" flag. This is could be used as a way to launch a reverse shell or execute live ruby code.
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
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
        - Image|endswith: '\ruby.exe'
        - OriginalFileName: 'ruby.exe'
    selection_cli:
        CommandLine|contains: ' -e'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
