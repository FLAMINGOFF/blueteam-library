---
title: Suspicious Execution of Powershell with Base64
summary: Commandline to launch powershell with a base64 payload
sigma_id: fb843269-508c-4b76-8b8d-88679db22ce7
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: frack113
date: '2022-01-02'
modified: '2023-01-05'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets
  - https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
  - https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_encode.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Execution of Powershell with Base64
id: fb843269-508c-4b76-8b8d-88679db22ce7
status: test
description: Commandline to launch powershell with a base64 payload
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.001/T1059.001.md#atomic-test-20---powershell-invoke-known-malicious-cmdlets
    - https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/
    - https://mikefrobbins.com/2017/06/15/simple-obfuscation-with-powershell-using-base64-encoding/
author: frack113
date: 2022-01-02
modified: 2023-01-05
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - \powershell.exe
            - \pwsh.exe
        CommandLine|contains:
            - ' -e '
            - ' -en '
            - ' -enc '
            - ' -enco'
            - ' -ec '
    filter_encoding:
        CommandLine|contains: ' -Encoding '
    filter_azure:
        ParentImage|contains:
            - 'C:\Packages\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows\'
            - '\gc_worker.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_powershell_encode/info.yml
```
