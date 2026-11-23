---
title: DNS Query to Wildcard DNS Services - Network
summary: |-
  Detects DNS queries to public wildcard DNS services that dynamically resolve subdomains to IP addresses embedded in the subdomain.
  Adversaries abuse these services to establish C2 channels or stage phishing infrastructure without registering a custom domain, potentially to evade detection and attribution.
sigma_id: 139ddcb3-ba90-4407-b0b1-1838131ce8e7
status: experimental
level: medium
platform: other
logsource: dns
tactics:
  - TA0011
techniques:
  - T1071.004
  - T1568
author: MahirAli Khan
date: '2026-11-05'
falsepositives:
  - Developers using nip.io or sslip.io to test local HTTPS setups or Kubernetes ingress rules without modifying /etc/hosts
  - CI/CD pipelines that provision ephemeral review environments with dynamically generated hostnames (e.g. PR-based preview deployments)
references:
  - https://nip.io/
  - https://sslip.io/
  - https://traefik.me/
  - https://github.polettix.it/ETOOBUSY/2022/10/09/nip-io-sslip-io/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/network/dns/net_dns_wildcard_dns_service.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DNS Query to Wildcard DNS Services - Network
id: 139ddcb3-ba90-4407-b0b1-1838131ce8e7
related:
    - id: 4f8a1c2e-7d3b-4e5f-9a6c-0b1d2e3f4a5b
      type: similar
status: experimental
description: |
    Detects DNS queries to public wildcard DNS services that dynamically resolve subdomains to IP addresses embedded in the subdomain.
    Adversaries abuse these services to establish C2 channels or stage phishing infrastructure without registering a custom domain, potentially to evade detection and attribution.
references:
    - https://nip.io/
    - https://sslip.io/
    - https://traefik.me/
    - https://github.polettix.it/ETOOBUSY/2022/10/09/nip-io-sslip-io/
author: MahirAli Khan
date: 2026-11-05
tags:
    - attack.command-and-control
    - attack.t1071.004
    - attack.t1568
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            # IP-embedding services (subdomain encodes an arbitrary IP)
            - '.1u.ms'
            - '.backname.io'
            - '.nip.io'
            - '.sslip.io'
            - '.traefik.me'
            - '.xip.io'
    condition: selection
falsepositives:
    - Developers using nip.io or sslip.io to test local HTTPS setups or Kubernetes ingress rules without modifying /etc/hosts
    - CI/CD pipelines that provision ephemeral review environments with dynamically generated hostnames (e.g. PR-based preview deployments)
level: medium
```
