# Linux Sudo Privilege Escalation Investigation using Wazuh

## Overview

This lab investigates Linux sudo privilege elevation using Wazuh. It focuses on understanding how authorized users obtain elevated privileges, how sudo activity is recorded by Linux, and how Wazuh identifies and reports privileged command execution.

The investigation was conducted on a Rocky Linux 9.8 virtual machine running Wazuh 4.13.1. The Linux account `abhinavmathur` was examined to understand its administrative group membership and sudo permissions. A controlled privilege elevation test was performed using `sudo /usr/bin/id`, which successfully executed the command with root privileges.

Linux authentication and PAM session records were then examined alongside Wazuh alerts. Rule ID 5402, describing successful sudo execution as root, was observed with a MITRE ATT&CK mapping to T1548.003 — Sudo and Sudo Caching.

The exercise also highlighted an important investigation requirement: a successful sudo detection must be correlated with its original command, source user, destination user, and execution context before classifying it as suspicious.

## Lab Objectives

- Understand Linux sudo privilege elevation and its security implications.
- Identify users belonging to the administrative `wheel` group.
- Examine sudoers permissions and determine which commands an account is authorized to execute.
- Review Linux authentication records and PAM session activity.
- Verify how Wazuh collects sudo-related events through journald.
- Generate a controlled successful sudo event using a non-root account.
- Identify relevant Wazuh sudo detection rules and their MITRE ATT&CK mappings.
- Correlate Wazuh alerts with underlying Linux authentication evidence.
- Distinguish legitimate administrative activity from potentially suspicious privilege escalation.
- Construct an evidence-based investigation timeline.

## Environment

| Component | Details |
|---|---|
| Virtualization | VMware |
| Operating System | Rocky Linux 9.8 (Blue Onyx) |
| Kernel | 5.14.0-687.31.1.el9_8.x86_64 |
| Architecture | x86-64 |
| Hostname | localhost |
| Wazuh Manager | 4.13.1 |
| Wazuh Revision | rc1 |
| Investigation Account | abhinavmathur |
| Account UID | 1000 |
| Administrative Group | wheel |
| Log Collection | journald |
| Authentication Log | /var/log/secure |
| Alert Output | /var/ossec/logs/alerts/alerts.json |

## Investigation Workflow

The investigation followed these stages:

1. **System baseline:** Identified the operating system, Wazuh version, current identity, and Manager service state.
2. **User authorization:** Examined the `wheel` group, user identity, sudoers configuration, and effective sudo permissions.
3. **Authentication log review:** Inspected `/var/log/secure` and systemd journal records for sudo activity.
4. **Controlled privilege elevation:** Switched to the non-root account `abhinavmathur`, cleared the cached sudo authentication timestamp, and executed `/usr/bin/id` through sudo.
5. **Wazuh detection review:** Examined sudo-related alerts and identified Rule ID 5402 and associated PAM events.
6. **Evidence correlation:** Compared the source user, destination user, executed command, timestamps, and Wazuh detection details.

## Key Findings

### 1. User Authorization

The account `abhinavmathur` was identified as a member of the `wheel` group.

The group membership check returned:

```text
wheel:x:10:abhinavmathur
```

The account identity showed:

```text
uid=1000(abhinavmathur)
gid=1000(abhinavmathur)
groups=1000(abhinavmathur),10(wheel)
```

The sudo permission review confirmed:

```text
User abhinavmathur may run the following commands on localhost:
    (ALL) ALL
```

The active sudoers rule was:

```text
%wheel  ALL=(ALL)       ALL
```

The example `NOPASSWD` rule was commented out. `visudo -c` also confirmed that the sudoers configuration parsed successfully.

### 2. Controlled Privilege Elevation

The account `abhinavmathur` was used to execute:

```bash
sudo -k
sudo /usr/bin/id
```

The command returned:

```text
uid=0(root) gid=0(root) groups=0(root)
```

This confirmed that the non-root account successfully executed the command with root privileges.

### 3. Wazuh Detection

Wazuh reported the following sudo-related detection:

| Attribute | Observed Value |
|---|---|
| Rule ID | 5402 |
| Rule Level | 3 |
| Description | Successful sudo to ROOT executed |
| Rule Groups | syslog, sudo |
| MITRE ATT&CK | T1548.003 |
| Technique | Sudo and Sudo Caching |
| Tactics | Privilege Escalation, Defense Evasion |

The captured Dashboard details showed `rule.firedtimes` as 16. This is the count reported in that alert view, not an independently established count of controlled test executions.

### 4. PAM Session Activity

Wazuh also reported PAM session events:

- Rule ID 5501 — PAM login session opened.
- Rule ID 5502 — PAM login session closed.

The captured records included a session for `abhinavmathur`, followed by session activity involving the root account.

These events provide additional context for investigating privileged sessions.

### 5. Command Attribution and Evidence Limitation

A detailed Rule ID 5402 record in the captured evidence identified:

```text
Source User: root
Destination User: root
Command: /bin/systemctl start wazuh-manager
```

The corresponding journal entry showed the sudo session being opened by `abhinavmathur(uid=0)`.

This indicates that the recorded service-start command was executed from a root-UID context. It should not be interpreted as direct evidence that the non-root controlled `/usr/bin/id` test generated that particular alert.

The controlled `/usr/bin/id` operation independently demonstrated successful elevation, but the available detailed alert record did not establish a direct one-to-one correlation between that command and the displayed Rule ID 5402 event.

## Wazuh Detection Query

The following DQL query can be used in Wazuh Dashboard Discover to review sudo-related and associated PAM events:

```text
rule.id: "5401" OR rule.id: "5402" OR rule.id: "5403" OR rule.id: "5404" OR rule.id: "5405" OR rule.id: "5406" OR rule.id: "5407" OR rule.id: "5501" OR rule.id: "5502"
```

Use the `wazuh-alerts-*` index pattern and an appropriate time range covering the investigation.

## Final Assessment

The investigation confirmed that `abhinavmathur` belonged to the administrative `wheel` group and was authorized to execute all commands through sudo. A controlled command executed from the non-root account successfully returned root identity.

Wazuh Rule ID 5402 and associated PAM session events were observed. The evidence also demonstrated why source-user and command attribution must be validated carefully: a separate Rule ID 5402 record identified a root-to-root service-start operation rather than the controlled `/usr/bin/id` command.

The lab successfully demonstrated sudo authorization review, controlled privilege elevation, authentication log examination, and Wazuh detection analysis. It did not establish malicious privilege escalation or unauthorized access.

## Scope and Safety

This lab focuses on legitimate, controlled sudo execution and its security monitoring.

It does not involve:
- Exploiting sudo vulnerabilities.
- Bypassing sudo authentication.
- Modifying sudoers permissions to obtain unauthorized access.
- Creating persistence or hiding privileged activity.
- Treating every successful sudo event as malicious.

Sensitive account information, passwords, and private system configuration must not be published in the repository.

## Future Enhancements

- Investigate repeated failed sudo attempts and unauthorized sudo usage.
- Monitor changes to `/etc/sudoers` and `/etc/sudoers.d/`.
- Detect unexpected additions to the `wheel` group.
- Correlate sudo execution with process creation and file integrity events.
- Develop a custom detection for unusual privileged command execution.
- Correlate sudo activity with an alert-to-ticket workflow.
