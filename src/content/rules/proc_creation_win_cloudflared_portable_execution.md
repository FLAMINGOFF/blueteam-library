---
title: Cloudflared Portable Execution
summary: Detects the execution of the "cloudflared" binary from a non standard location.
sigma_id: fadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1090.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-12-20'
falsepositives:
  - Legitimate usage of Cloudflared portable versions
references:
  - https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/
  - https://github.com/cloudflare/cloudflared
  - https://www.intrinsec.com/akira_ransomware/
  - https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
  - https://github.com/cloudflare/cloudflared/releases
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cloudflared_portable_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Cloudflared Portable Execution
id: fadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd
status: test
description: |
    Detects the execution of the "cloudflared" binary from a non standard location.
references:
    - https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/
    - https://github.com/cloudflare/cloudflared
    - https://www.intrinsec.com/akira_ransomware/
    - https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
    - https://github.com/cloudflare/cloudflared/releases
author: Nasreddine Bencherchali (Nextron Systems)
tags:
    - attack.command-and-control
    - attack.t1090.001
date: 2023-12-20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cloudflared.exe'
    filter_main_admin_location:
        Image|contains:
            - ':\Program Files (x86)\cloudflared\'
            - ':\Program Files\cloudflared\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate usage of Cloudflared portable versions
level: medium
```
