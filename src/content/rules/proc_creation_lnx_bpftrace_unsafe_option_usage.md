---
title: BPFtrace Unsafe Option Usage
summary: Detects the usage of the unsafe bpftrace option
sigma_id: f8341cb2-ee25-43fa-a975-d8a5a9714b39
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059.004
author: Andreas Hunkeler (@Karneades)
date: '2022-02-11'
falsepositives:
  - Legitimate usage of the unsafe option
references:
  - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
  - https://bpftrace.org/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_bpftrace_unsafe_option_usage.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: BPFtrace Unsafe Option Usage
id: f8341cb2-ee25-43fa-a975-d8a5a9714b39
status: test
description: Detects the usage of the unsafe bpftrace option
references:
    - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
    - https://bpftrace.org/
author: Andreas Hunkeler (@Karneades)
date: 2022-02-11
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: 'bpftrace'
        CommandLine|contains: '--unsafe'
    condition: selection
falsepositives:
    - Legitimate usage of the unsafe option
level: medium
```
