---
title: Potentially Suspicious WebDAV LNK Execution
summary: Detects possible execution via LNK file accessed on a WebDAV server.
sigma_id: 1412aa78-a24c-4abd-83df-767dfb2c5bbe
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
  - T1204
author: Micah Babinski
date: '2023-08-21'
falsepositives:
  - Unknown
references:
  - https://www.trellix.com/en-us/about/newsroom/stories/research/beyond-file-search-a-novel-method.html
  - https://micahbabinski.medium.com/search-ms-webdav-and-chill-99c5b23ac462
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_webdav_lnk_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious WebDAV LNK Execution
id: 1412aa78-a24c-4abd-83df-767dfb2c5bbe
related:
    - id: f0507c0f-a3a2-40f5-acc6-7f543c334993
      type: similar
status: test
description: Detects possible execution via LNK file accessed on a WebDAV server.
references:
    - https://www.trellix.com/en-us/about/newsroom/stories/research/beyond-file-search-a-novel-method.html
    - https://micahbabinski.medium.com/search-ms-webdav-and-chill-99c5b23ac462
author: Micah Babinski
date: 2023-08-21
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1204
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\explorer.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
        CommandLine|contains: '\DavWWWRoot\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
