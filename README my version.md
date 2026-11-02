# Linux-Sudo-Privilege-Escalation-Investigation-Wazuh
## Overview
Linux uses `sudo` (superuser do) to allow authorized users to execute commands with elevated privileges, commonly as the root user. This provides controlled administrative access without requiring users to log in directly as root.

Although sudo is a legitimate system administration mechanism, attackers may abuse it to obtain elevated privileges, execute unauthorized commands, modify security configurations, or establish persistence.

A sudo privilege escalation investigation focuses on understanding who requested elevated access, which command was executed, whether the activity was authorized, and what happened afterward.

### How Sudo Privilege Escalation Works

When an authorized user executes a command using sudo:

1. The user requests permission to execute a command with elevated privileges.
2. Linux evaluates the user's sudo permissions and authentication requirements.
3. If permitted, sudo executes the requested command under the target user's identity, commonly root.
4. Authentication and command-execution activity is recorded in system logs.
5. Wazuh collects and analyzes the available log events.
6. Detection rules identify successful or unsuccessful sudo activity.
7. The SOC analyst investigates the account, command, timestamp, target identity, and surrounding activity.

### Role of Wazuh

Wazuh helps investigate sudo activity by collecting Linux authentication logs, decoding sudo-related messages, and evaluating them against detection rules.

The following are relevant built-in Wazuh rules commonly found in the syslog ruleset:

| Rule ID | Description | Rule Level |
|---|---|---:|
| 5401 | Failed attempt to run sudo | 5 |
| 5402 | Successful sudo to ROOT executed | 3 |
| 5403 | First time user executed sudo | 4 |
| 5404 | Three failed sudo password attempts | 10 |
| 5405 | Unauthorized user attempted to use sudo | 5 |
| 5406 | Command not allowed | 5 |
| 5407 | Successful sudo executed | 3 |

These rule definitions and levels should be checked against the ruleset installed in the lab.

### Important Log Events

| Event | Investigation Value |
|---|---|
| Successful sudo execution | Identifies privileged command execution |
| Failed sudo authentication | May indicate incorrect credentials or attempted unauthorized access |
| User not in sudoers | Identifies an attempted use of sudo without authorization |
| Command not allowed | Identifies a command rejected by sudo policy |
| PAM session opened | Indicates a privileged session was established |
| PAM session closed | Indicates a privileged session ended |

### Important Fields to Investigate

| Field | Investigation Purpose |
|---|---|
| Source user | Identifies the account requesting elevated privileges |
| Destination user | Identifies the account under which the command ran |
| Command | Shows what was executed |
| TTY | Identifies the terminal associated with the activity |
| PWD | Shows the working directory |
| Timestamp | Establishes when the activity occurred |
| Agent | Identifies the system generating the event |
| Rule ID and level | Identifies the triggered detection and its assigned severity |
| Full log | Preserves the original authentication event for validation |

### Legitimate Activity Versus Suspicious Activity

A successful sudo event is not automatically malicious. Administrators routinely use sudo for system maintenance, troubleshooting, service management, and security operations.

The investigation must consider:

- Whether the account was expected to have administrative privileges.
- Whether the executed command was appropriate for the user's role.
- Whether the activity occurred during an expected maintenance window.
- Whether several failed sudo attempts preceded successful elevation.
- Whether sudoers configuration or administrative group membership changed.
- Whether unexpected accounts or processes subsequently used elevated privileges.

**Important distinction:** Wazuh Rule ID 5402 identifies successful sudo execution as root. It does not independently establish malicious privilege escalation. The command, source user, authorization context, and surrounding activity determine whether further investigation is warranted.

This lab investigates Linux sudo privilege elevation using Wazuh. It focuses on understanding how authorized users obtain elevated privileges, how sudo activity is recorded by Linux, and how Wazuh identifies and reports privileged command execution.

The investigation was conducted on a Rocky Linux 9.8 virtual machine running Wazuh 4.13.1. The Linux account `abhinavmathur` was examined to understand its administrative group membership and sudo permissions. A controlled privilege elevation test was performed using `sudo /usr/bin/id`, which successfully executed the command with root privileges.

Linux authentication and PAM session records were then examined alongside Wazuh alerts. Rule ID 5402, describing successful sudo execution as root, was observed with a MITRE ATT&CK mapping to T1548.003 — Sudo and Sudo Caching.

The exercise also highlighted an important investigation requirement: a successful sudo detection must be correlated with its original command, source user, destination user, and execution context before classifying it as suspicious.

## Lab Objectives

The objectives of this lab are to:

- Understand how Linux sudo provides controlled access to elevated privileges.
- Identify users with administrative permissions through group membership and sudoers configuration.
- Examine effective sudo permissions and determine which commands an account is authorized to execute.
- Inspect Linux authentication logs and systemd journal records for privileged command execution.
- Understand how PAM session events provide additional visibility into user and root session activity.
- Perform a controlled sudo privilege elevation test using a non-root account.
- Identify relevant Wazuh detection rules for successful and unsuccessful sudo activity.
- Investigate Rule ID 5402 and understand its association with MITRE ATT&CK technique T1548.003.
- Correlate Wazuh alerts with original authentication records using timestamps, source users, destination users, and command details.
- Examine related PAM session events to establish the context of privileged activity.
- Distinguish legitimate administrative operations from potentially suspicious privilege escalation.
- Identify potential indicators of sudo misuse, including unauthorized access, repeated authentication failures, and unexpected changes to sudoers permissions.
- Construct an investigation timeline using available system logs and Wazuh alert evidence.
- Document verified findings, evidence gaps, and unresolved correlations without assuming that successful sudo execution indicates malicious activity.

## Lab Scenario

A Rocky Linux 9.8 virtual machine running Wazuh 4.13.1 is being investigated to understand how Linux privileged command execution is monitored and how potentially suspicious sudo activity can be identified.

The investigation focuses on the Linux account `abhinavmathur`, which belongs to the administrative `wheel` group. An examination of the sudoers configuration confirms that the account is permitted to execute all commands through sudo. Although this access is legitimate for system administration, unrestricted privileges can also be abused if an account is compromised or used without authorization.

To understand how privilege elevation is recorded and detected, a controlled test is performed using the non-root account. After clearing the cached sudo authentication timestamp, the account executes `/usr/bin/id` through sudo. The command successfully returns UID 0, confirming that the requested operation was executed with root privileges.

Wazuh is then used to investigate the resulting privileged activity and related authentication events. The assessment covers the following areas:

- **User authorization:** Examine administrative group membership, sudoers configuration, and the effective permissions assigned to the account.
- **Authentication monitoring:** Review Linux authentication records and systemd journal entries to identify sudo commands and authentication outcomes.
- **Controlled privilege elevation:** Perform a legitimate sudo operation and verify the transition from the non-root account to root.
- **Wazuh detection:** Examine sudo-related detection rules, particularly Rule ID 5402, which identifies successful sudo execution as root.
- **PAM session correlation:** Review Rule IDs 5501 and 5502 to understand how session-opening and session-closing events provide additional investigation context.
- **MITRE ATT&CK mapping:** Examine the association between successful sudo activity and T1548.003 — Sudo and Sudo Caching.
- **Command attribution:** Compare the source user, destination user, executed command, timestamp, and host information across authentication records and Wazuh alerts.

During the investigation, Wazuh reports Rule ID 5402 at level 3, with a MITRE ATT&CK mapping to T1548.003. Related PAM session events are also observed. However, the detailed Rule ID 5402 record available for examination identifies a separate `/bin/systemctl start wazuh-manager` command executed in a root-UID context. It is therefore not treated as direct evidence that the controlled `/usr/bin/id` test generated that particular alert.

The investigation must distinguish legitimate administrative activity from potentially suspicious privilege escalation by examining account permissions, command execution, authentication context, and surrounding events.

**Scenario objective:** Investigate Linux sudo privilege elevation using Wazuh, correlate authentication and PAM records with security alerts, understand the relevant detection rules and MITRE ATT&CK mapping, and determine whether the available evidence supports normal administrative activity or requires further investigation.

**Scope limitation:** This lab demonstrates authorized sudo privilege elevation and its monitoring through Wazuh. It does not involve exploiting sudo vulnerabilities, bypassing authentication, or establishing unauthorized access. Successful privilege elevation and a Wazuh detection do not independently establish malicious activity or system compromise.

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

