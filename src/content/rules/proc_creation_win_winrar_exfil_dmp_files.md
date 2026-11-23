---
title: Winrar Compressing Dump Files
summary: Detects execution of WinRAR in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
sigma_id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1560.001
author: Florian Roth (Nextron Systems)
date: '2022-01-04'
modified: '2023-09-12'
falsepositives:
  - Legitimate use of WinRAR with a command line in which ".dmp" or ".dump" appears accidentally
  - Legitimate use of WinRAR to compress WER ".dmp" files for troubleshooting
references:
  - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winrar_exfil_dmp_files.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Winrar Compressing Dump Files
id: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
related:
    - id: ec570e53-4c76-45a9-804d-dc3f355ff7a7
      type: similar
status: test
description: Detects execution of WinRAR in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
references:
    - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
author: Florian Roth (Nextron Systems)
date: 2022-01-04
modified: 2023-09-12
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\rar.exe'
              - '\winrar.exe'
        - Description: 'Command line RAR'
    selection_extension:
        CommandLine|contains:
            - '.dmp'
            - '.dump'
            - '.hdmp'
    condition: all of selection_*
falsepositives:
    - Legitimate use of WinRAR with a command line in which ".dmp" or ".dump" appears accidentally
    - Legitimate use of WinRAR to compress WER ".dmp" files for troubleshooting
level: medium
```
