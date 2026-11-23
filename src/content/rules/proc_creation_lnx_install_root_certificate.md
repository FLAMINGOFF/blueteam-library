---
title: Install Root Certificate
summary: Detects installation of new certificate on the system which attackers may use to avoid warnings when connecting to controlled web servers or C2s
sigma_id: 78a80655-a51e-4669-bc6b-e9d206a462ee
status: test
level: low
platform: linux
logsource: linux / process_creation
tactics:
  - TA0112
techniques:
  - T1553.004
author: Ömer Günal, oscd.community
date: '2020-10-05'
modified: '2026-10-04'
falsepositives:
  - Legitimate administration activities
references:
  - https://www.trendmicro.com/en_us/research/14/h/finding-holes-operation-emmental.html
  - https://www.kaspersky.com/blog/lenovo-pc-with-adware-superfish-preinstalled/
  - https://www.cisa.gov/news-events/alerts/2015/02/20/lenovo-superfish-adware-vulnerable-https-spoofing
  - https://capec.mitre.org/data/definitions/479.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_install_root_certificate.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Install Root Certificate
id: 78a80655-a51e-4669-bc6b-e9d206a462ee
status: test
description: Detects installation of new certificate on the system which attackers may use to avoid warnings when connecting to controlled web servers or C2s
references:
    - https://www.trendmicro.com/en_us/research/14/h/finding-holes-operation-emmental.html
    - https://www.kaspersky.com/blog/lenovo-pc-with-adware-superfish-preinstalled/
    - https://www.cisa.gov/news-events/alerts/2015/02/20/lenovo-superfish-adware-vulnerable-https-spoofing
    - https://capec.mitre.org/data/definitions/479.html
author: Ömer Günal, oscd.community
date: 2020-10-05
modified: 2026-10-04
tags:
    - attack.defense-impairment
    - attack.t1553.004
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '/update-ca-certificates'
            - '/update-ca-trust'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
simulation:
    - type: atomic-red-team
      name: Install root CA on CentOS/RHEL
      technique: T1553.004
      atomic_guid: 9c096ec4-fd42-419d-a762-d64cc950627e
    - type: atomic-red-team
      name: Install root CA on Debian/Ubuntu
      technique: T1553.004
      atomic_guid: 53bcf8a0-1549-4b85-b919-010c56d724ff
```
