---
title: NodeJS Execution of JavaScript File
summary: >-
  Detects execution of JavaScript or JSC files using NodeJs binary node.exe, that could be potentially suspicious.

  Node.js is a popular open-source JavaScript runtime that runs code outside browsers and is widely used for both frontend and backend development.

  Adversaries have been observed abusing Node.js to disguise malware as legitimate processes, evade security defenses, and maintain persistence within target systems.

  Because Node.js is commonly used, this rule may generate false positives in some environments. However, if such activity is unusual in your environment, it is highly suspicious and warrants
  immediate investigation.
sigma_id: ba3874b9-0fae-465f-836c-eb5d071a1789
status: experimental
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.007
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-04-21'
falsepositives:
  - Legitimate use of node.exe to execute JavaScript or JSC files on your environment
references:
  - https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_security_susp_node_js_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: NodeJS Execution of JavaScript File
id: ba3874b9-0fae-465f-836c-eb5d071a1789
status: experimental
description: |
    Detects execution of JavaScript or JSC files using NodeJs binary node.exe, that could be potentially suspicious.
    Node.js is a popular open-source JavaScript runtime that runs code outside browsers and is widely used for both frontend and backend development.
    Adversaries have been observed abusing Node.js to disguise malware as legitimate processes, evade security defenses, and maintain persistence within target systems.
    Because Node.js is commonly used, this rule may generate false positives in some environments. However, if such activity is unusual in your environment, it is highly suspicious and warrants immediate investigation.
references:
    - https://www.microsoft.com/en-us/security/blog/2025/04/15/threat-actors-misuse-node-js-to-deliver-malware-and-other-malicious-payloads/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
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
        CommandLine|contains: '.js'
    condition: all of selection_*
falsepositives:
    - Legitimate use of node.exe to execute JavaScript or JSC files on your environment
level: low
```
