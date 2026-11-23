---
title: AWS KMS Imported Key Material Usage
summary: Detects the import or deletion of key material in AWS KMS, which can be used as part of ransomware attacks. This activity is uncommon and provides a high certainty signal.
sigma_id: 1279262f-1464-422f-ac0d-5b545320c526
status: experimental
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0040
  - TA0042
techniques:
  - T1486
  - T1608.003
author: toopricey
date: '2025-10-18'
falsepositives:
  - Legitimate use cases for imported key material are rare, but may include, Organizations with hybrid cloud architectures that import external key material for compliance requirements.
  - Development or testing environments that simulate external key management scenarios. Even in these cases, such activity is typically infrequent and should not add significant noise.
references:
  - https://www.chrisfarris.com/post/effective-aws-ransomware/
  - https://docs.aws.amazon.com/kms/latest/developerguide/ct-importkeymaterial.html
  - https://docs.aws.amazon.com/kms/latest/developerguide/ct-deleteimportedkeymaterial.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_kms_import_key_material.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS KMS Imported Key Material Usage
id: 1279262f-1464-422f-ac0d-5b545320c526
status: experimental
description: |
    Detects the import or deletion of key material in AWS KMS, which can be used as part of ransomware attacks. This activity is uncommon and provides a high certainty signal.
references:
    - https://www.chrisfarris.com/post/effective-aws-ransomware/
    - https://docs.aws.amazon.com/kms/latest/developerguide/ct-importkeymaterial.html
    - https://docs.aws.amazon.com/kms/latest/developerguide/ct-deleteimportedkeymaterial.html
author: toopricey
date: 2025-10-18
tags:
    - attack.impact
    - attack.t1486
    - attack.resource-development
    - attack.t1608.003
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: 'kms.amazonaws.com'
        eventName:
            - 'ImportKeyMaterial'
            - 'DeleteImportedKeyMaterial'
    condition: selection
falsepositives:
    - Legitimate use cases for imported key material are rare, but may include, Organizations with hybrid cloud architectures that import external key material for compliance requirements.
    - Development or testing environments that simulate external key management scenarios. Even in these cases, such activity is typically infrequent and should not add significant noise.
level: high
```
