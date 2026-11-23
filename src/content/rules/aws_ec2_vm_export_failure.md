---
title: AWS EC2 VM Export Failure
summary: An attempt to export an AWS EC2 instance has been detected. A VM Export might indicate an attempt to extract information from an instance.
sigma_id: 54b9a76a-3c71-4673-b4b3-2edb4566ea7b
status: test
level: low
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0009
  - TA0010
techniques:
  - T1005
  - T1537
author: Diogo Braz
date: '2020-04-16'
modified: '2022-10-05'
falsepositives: []
references:
  - https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html#export-instance
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/cloud/aws/cloudtrail/aws_ec2_vm_export_failure.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AWS EC2 VM Export Failure
id: 54b9a76a-3c71-4673-b4b3-2edb4566ea7b
status: test
description: An attempt to export an AWS EC2 instance has been detected. A VM Export might indicate an attempt to extract information from an instance.
references:
    - https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html#export-instance
author: Diogo Braz
date: 2020-04-16
modified: 2022-10-05
tags:
    - attack.collection
    - attack.t1005
    - attack.exfiltration
    - attack.t1537
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'CreateInstanceExportTask'
        eventSource: 'ec2.amazonaws.com'
    filter1:
        errorMessage|contains: '*'
    filter2:
        errorCode|contains: '*'
    filter3:
        responseElements|contains: 'Failure'
    condition: selection and not 1 of filter*
level: low
```
