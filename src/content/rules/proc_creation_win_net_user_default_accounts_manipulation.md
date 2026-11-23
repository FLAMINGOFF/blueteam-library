---
title: Suspicious Manipulation Of Default Accounts Via Net.EXE
summary: Detects suspicious manipulations of default accounts such as 'administrator' and 'guest'. For example 'enable' or 'disable' accounts or change the password...etc
sigma_id: 5b768e71-86f2-4879-b448-81061cbae951
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1560.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-01'
modified: '2023-02-21'
falsepositives:
  - Some false positives could occur with the admin or guest account. It depends on the scripts being used by the admins in your env. If you experience a lot of FP you could reduce the level to medium
references:
  - https://www.trellix.com/en-sg/about/newsroom/stories/threat-labs/lockergoga-ransomware-family-used-in-targeted-attacks.html
  - https://redacted.com/blog/bianlian-ransomware-gang-gives-it-a-go/
  - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_net_user_default_accounts_manipulation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Manipulation Of Default Accounts Via Net.EXE
id: 5b768e71-86f2-4879-b448-81061cbae951
status: test
description: Detects suspicious manipulations of default accounts such as 'administrator' and 'guest'. For example 'enable' or 'disable' accounts or change the password...etc
references:
    - https://www.trellix.com/en-sg/about/newsroom/stories/threat-labs/lockergoga-ransomware-family-used-in-targeted-attacks.html
    - https://redacted.com/blog/bianlian-ransomware-gang-gives-it-a-go/
    - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-01
modified: 2023-02-21
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_user_option:
        CommandLine|contains: ' user '
    selection_username:
        CommandLine|contains:
            # Note: We need to write the full account name for cases starting with 'admin' to avoid lookups only with the user flag
            - ' Järjestelmänvalvoja ' # Finish
            - ' Rendszergazda ' # Hungarian
            - ' Администратор ' # Russian
            - ' Administrateur ' # French
            - ' Administrador ' # Portuguese (Brazil + Portugal) + Spanish
            - ' Administratör ' # Swedish
            - ' Administrator ' # English
            - ' guest '
            - ' DefaultAccount '
            # The cases below are for when an attacker requests the net command via 'cmd /c....'
            # First in double quotes
            - ' "Järjestelmänvalvoja" ' # Finish
            - ' "Rendszergazda" ' # Hungarian
            - ' "Администратор" ' # Russian
            - ' "Administrateur" ' # French
            - ' "Administrador" ' # Portuguese (Brazil + Portugal) + Spanish
            - ' "Administratör" ' # Swedish
            - ' "Administrator" ' # English
            - ' "guest" '
            - ' "DefaultAccount" '
            # Second in single quotes
            - " 'Järjestelmänvalvoja' " # Finish
            - " 'Rendszergazda' " # Hungarian
            - " 'Администратор' " # Russian
            - " 'Administrateur' " # French
            - " 'Administrador' " # Portuguese (Brazil + Portugal) + Spanish
            - " 'Administratör' " # Swedish
            - " 'Administrator' " # English
            - " 'guest' "
            - " 'DefaultAccount' "
    filter:
        CommandLine|contains|all:
            - 'guest'
            - '/active no'
    condition: all of selection_* and not filter
falsepositives:
    - Some false positives could occur with the admin or guest account. It depends on the scripts being used by the admins in your env. If you experience a lot of FP you could reduce the level to medium
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_net_user_default_accounts_manipulation/info.yml
```
