---
title: Potentially Suspicious Inline JavaScript Execution via NodeJS Binary
summary: Detects potentially suspicious inline JavaScript execution using Node.js with specific keywords in the command line.
sigma_id: 8537c866-072e-460d-bfff-aaf39cbd73d3
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.007
author: Microsoft (idea), Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-04-21'
falsepositives:
  - Legitimate scripts using Node.js with these modules
references:
  - https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_inline_node_js_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Inline JavaScript Execution via NodeJS Binary
id: 8537c866-072e-460d-bfff-aaf39cbd73d3
status: experimental
description: Detects potentially suspicious inline JavaScript execution using Node.js with specific keywords in the command line.
references:
    - https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/
author: Microsoft (idea), Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-04-21
tags:
    - attack.execution
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\node.exe'
        - OriginalFileName: 'node.exe'
        - Product: 'Node.js'
    selection_cmd:
        CommandLine|contains|all:
            - 'http'
            - 'execSync'
            - 'spawn'
            - 'fs'
            - 'path'
            - 'zlib'
    condition: all of selection_*
falsepositives:
    - Legitimate scripts using Node.js with these modules
level: medium
```
