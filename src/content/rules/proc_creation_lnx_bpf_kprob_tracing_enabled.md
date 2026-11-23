---
title: Enable BPF Kprobes Tracing
summary: Detects common command used to enable bpf kprobes tracing
sigma_id: 7692f583-bd30-4008-8615-75dab3f08a99
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-25'
falsepositives:
  - Unknown
references:
  - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
  - https://bpftrace.org/
  - https://www.kernel.org/doc/html/v5.0/trace/kprobetrace.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_bpf_kprob_tracing_enabled.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Enable BPF Kprobes Tracing
id: 7692f583-bd30-4008-8615-75dab3f08a99
status: test
description: Detects common command used to enable bpf kprobes tracing
references:
    - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
    - https://bpftrace.org/
    - https://www.kernel.org/doc/html/v5.0/trace/kprobetrace.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-25
tags:
    - attack.execution
    - attack.stealth
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'echo 1 >'
            - '/sys/kernel/debug/tracing/events/kprobes/'
        CommandLine|contains:
            - '/myprobe/enable'
            - '/myretprobe/enable'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
