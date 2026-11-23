---
title: Copy Passwd Or Shadow From TMP Path
summary: Detects when the file "passwd" or "shadow" is copied from tmp path
sigma_id: fa4aaed5-4fe0-498d-bbc0-08e3346387ba
status: test
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0006
techniques:
  - T1552.001
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: '2023-01-31'
falsepositives:
  - Unknown
references:
  - https://blogs.blackberry.com/
  - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Copy Passwd Or Shadow From TMP Path
id: fa4aaed5-4fe0-498d-bbc0-08e3346387ba
status: test
description: Detects when the file "passwd" or "shadow" is copied from tmp path
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-31
tags:
    - attack.credential-access
    - attack.t1552.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_img:
        Image|endswith: '/cp'
    selection_path:
        CommandLine|contains: '/tmp/'
    selection_file:
        CommandLine|contains:
            - 'passwd'
            - 'shadow'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
