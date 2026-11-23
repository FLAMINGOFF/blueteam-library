---
title: Suspicious Velociraptor Child Process
summary: >-
  Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further
  attacks.
sigma_id: 4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
  - TA0003
techniques:
  - T1219
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-08-29'
falsepositives:
  - >-
    Legitimate administrators or incident responders might use Velociraptor to execute scripts or tools. However, the combination of Velociraptor spawning these specific processes with these command
    lines is suspicious. Tuning may be required to exclude known administrative actions or specific scripts.
references:
  - https://news.sophos.com/en-us/2025/08/26/velociraptor-incident-response-tool-abused-for-remote-access/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_velociraptor_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Velociraptor Child Process
id: 4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c
status: experimental
description: Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further attacks.
references:
    - https://news.sophos.com/en-us/2025/08/26/velociraptor-incident-response-tool-abused-for-remote-access/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-08-29
tags:
    - attack.command-and-control
    - attack.persistence
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\Velociraptor.exe'
    selection_child_vscode_tunnel:
        CommandLine|contains|all:
            - 'code.exe'
            - 'tunnel'
            - '--accept-server-license-terms'
    selection_child_msiexec:
        CommandLine|contains|all:
            - 'msiexec'
            - '/i'
            - 'http'
    selection_child_powershell:
        Image|endswith:
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest '
            - 'IWR '
            - '.DownloadFile'
            - '.DownloadString'
    # Add more child process patterns as needed
    condition: selection_parent and 1 of selection_child_*
falsepositives:
    - Legitimate administrators or incident responders might use Velociraptor to execute scripts or tools. However, the combination of Velociraptor spawning these specific processes with these command lines is suspicious. Tuning may be required to exclude known administrative actions or specific scripts.
level: high
```
