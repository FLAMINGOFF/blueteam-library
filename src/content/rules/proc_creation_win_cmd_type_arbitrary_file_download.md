---
title: Potential Download/Upload Activity Using Type Command
summary: Detects usage of the "type" command to download/upload data from WebDAV server
sigma_id: aa0b3a82-eacc-4ec3-9150-b5a9a3e3f82f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-12-14'
falsepositives:
  - Unknown
references:
  - https://mr0range.com/a-new-lolbin-using-the-windows-type-command-to-upload-download-files-81d7b6179e22
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cmd_type_arbitrary_file_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Download/Upload Activity Using Type Command
id: aa0b3a82-eacc-4ec3-9150-b5a9a3e3f82f
status: test
description: Detects usage of the "type" command to download/upload data from WebDAV server
references:
    - https://mr0range.com/a-new-lolbin-using-the-windows-type-command-to-upload-download-files-81d7b6179e22
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-14
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    product: windows
    category: process_creation
detection:
    # Note that since built in CMD commands do not trigger a process creation. This would be detected only if used in a "/c" command
    selection_upload:
        CommandLine|contains|all:
            - 'type '
            - ' > \\\\'
    selection_download:
        CommandLine|contains|all:
            - 'type \\\\'
            - ' > ' # Space are added to increase atom length and speed up matching. If your backend can handle this remove the space
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
```
