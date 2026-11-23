---
title: Suspicious Parent Double Extension File Execution
summary: Detect execution of suspicious double extension files in ParentCommandLine
sigma_id: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036.007
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-06'
modified: '2023-02-28'
falsepositives:
  - Unknown
references:
  - https://www.virustotal.com/gui/file/7872d8845a332dce517adae9c3389fde5313ff2fed38c2577f3b498da786db68/behavior
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bluebottle-banks-targeted-africa
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_double_extension_parent.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Parent Double Extension File Execution
id: 5e6a80c8-2d45-4633-9ef4-fa2671a39c5c
related:
    - id: 1cdd9a09-06c9-4769-99ff-626e2b3991b8 # Image/CommandLine
      type: derived
status: test
description: Detect execution of suspicious double extension files in ParentCommandLine
references:
    - https://www.virustotal.com/gui/file/7872d8845a332dce517adae9c3389fde5313ff2fed38c2577f3b498da786db68/behavior
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/bluebottle-banks-targeted-africa
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-06
modified: 2023-02-28
tags:
    - attack.stealth
    - attack.t1036.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - ParentImage|endswith:
              - '.doc.lnk'
              - '.docx.lnk'
              - '.xls.lnk'
              - '.xlsx.lnk'
              - '.ppt.lnk'
              - '.pptx.lnk'
              - '.rtf.lnk'
              - '.pdf.lnk'
              - '.txt.lnk'
              - '.doc.js'
              - '.docx.js'
              - '.xls.js'
              - '.xlsx.js'
              - '.ppt.js'
              - '.pptx.js'
              - '.rtf.js'
              - '.pdf.js'
              - '.txt.js'
        - ParentCommandLine|contains:
              - '.doc.lnk'
              - '.docx.lnk'
              - '.xls.lnk'
              - '.xlsx.lnk'
              - '.ppt.lnk'
              - '.pptx.lnk'
              - '.rtf.lnk'
              - '.pdf.lnk'
              - '.txt.lnk'
              - '.doc.js'
              - '.docx.js'
              - '.xls.js'
              - '.xlsx.js'
              - '.ppt.js'
              - '.pptx.js'
              - '.rtf.js'
              - '.pdf.js'
              - '.txt.js'
    condition: selection
falsepositives:
    - Unknown
level: high
```
