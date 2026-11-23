---
title: Perl Inline Command Execution
summary: Detects execution of perl using the "-e"/"-E" flags. This is could be used as a way to launch a reverse shell or execute live perl code.
sigma_id: f426547a-e0f7-441a-b63e-854ac5bdf54d
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
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_perl_inline_command_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Perl Inline Command Execution
id: f426547a-e0f7-441a-b63e-854ac5bdf54d
status: test
description: Detects execution of perl using the "-e"/"-E" flags. This is could be used as a way to launch a reverse shell or execute live perl code.
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
        - Image|endswith: '\perl.exe'
        - OriginalFileName: 'perl.exe' # Also covers perlX.XX.exe
    selection_cli:
        CommandLine|contains: ' -e'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
