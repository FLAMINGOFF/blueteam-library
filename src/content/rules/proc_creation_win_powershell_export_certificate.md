---
title: Certificate Exported Via PowerShell
summary: Detects calls to cmdlets that are used to export certificates from the local certificate store. Threat actors were seen abusing this to steal private keys from compromised machines.
sigma_id: 9e716b33-63b2-46da-86a4-bd3c3b9b5dfb
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0002
techniques:
  - T1552.004
  - T1059.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-18'
falsepositives:
  - Legitimate certificate exports by administrators. Additional filters might be required.
references:
  - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-112a
  - https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate?view=windowsserver2022-ps
  - https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_export_certificate.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Certificate Exported Via PowerShell
id: 9e716b33-63b2-46da-86a4-bd3c3b9b5dfb
related:
    - id: aa7a3fce-bef5-4311-9cc1-5f04bb8c308c
      type: similar
status: test
description: Detects calls to cmdlets that are used to export certificates from the local certificate store. Threat actors were seen abusing this to steal private keys from compromised machines.
references:
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar21-112a
    - https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate?view=windowsserver2022-ps
    - https://www.splunk.com/en_us/blog/security/breaking-the-chain-defending-against-certificate-services-abuse.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-18
tags:
    - attack.credential-access
    - attack.execution
    - attack.t1552.004
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'Export-PfxCertificate '
            - 'Export-Certificate '
    condition: selection
falsepositives:
    - Legitimate certificate exports by administrators. Additional filters might be required.
level: medium
```
