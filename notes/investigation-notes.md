
# Investigation Notes — Linux Sudo Privilege Escalation Investigation using Wazuh

## 1. Investigation Summary

This investigation examined Linux sudo authorization, controlled privilege elevation, authentication logging, PAM session activity, and Wazuh detection.

The investigation target was a Rocky Linux 9.8 virtual machine running Wazuh 4.13.1.

The account `abhinavmathur` was identified as a member of the `wheel` group with permission to execute all commands through sudo. A controlled test was performed by switching from the root shell to the non-root account and executing `/usr/bin/id` through sudo.

The command successfully returned UID 0, confirming privilege elevation.

Wazuh reported Rule ID 5402, associated with successful sudo execution as root, along with PAM session events. However, the detailed Rule ID 5402 event available in the captured evidence identified a separate root-to-root service-start command. This distinction was retained during the investigation.

## 2. Environment Baseline

The system baseline was established using `hostnamectl`, `whoami`, `id`, and the Wazuh control utility.

| Attribute | Observed Value |
|---|---|
| Hostname | localhost |
| Operating System | Rocky Linux 9.8 (Blue Onyx) |
| Kernel | 5.14.0-687.31.1.el9_8.x86_64 |
| Virtualization | VMware |
| Architecture | x86-64 |
| Current baseline identity | root |
| Wazuh Version | 4.13.1 |
| Wazuh Revision | rc1 |
| Wazuh Type | server |
| Manager Service | active |

The Wazuh Manager was active during the baseline checks.

## 3. User and Privilege Review

### Account Identification

The regular user account was identified through the local account database.

```text
abhinavmathur        UID=1000 HOME=/home/abhinavmathur
```

The group membership query returned:

```text
wheel:x:10:abhinavmathur
```

The account identity was:

```text
uid=1000(abhinavmathur)
gid=1000(abhinavmathur)
groups=1000(abhinavmathur),10(wheel)
```

This established that the account belonged to the administrative `wheel` group.

### Sudo Authorization

The following command was used:

```bash
sudo -l -U abhinavmathur
```

The output included:

```text
User abhinavmathur may run the following commands on localhost:
    (ALL) ALL
```

This confirmed that the account was permitted to execute all commands as any target user through sudo.

### Sudoers Configuration

The syntax validation command:

```bash
sudo visudo -c
```

returned:

```text
/etc/sudoers: parsed OK
```

The relevant active rule was:

```text
%wheel  ALL=(ALL)       ALL
```

The following example was commented out:

```text
# %wheel        ALL = (ALL)       NOPASSWD: ALL
```

No active `NOPASSWD: ALL` rule was identified in the captured output.

**Assessment:** The user had broad administrative sudo privileges through the `wheel` group. The available evidence did not establish that these permissions were unauthorized.

## 4. Authentication Log Review

The authentication log file was present:

```text
-rw-------. 1 root root 17K Nov  2 07:26 /var/log/secure
```

The Wazuh Manager configuration contained an existing journald collection block:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```

This provided the configured journal-based log collection path used by the investigation.

The following command was used to examine sudo records:

```bash
sudo journalctl _COMM=sudo --since "30 minutes ago" --no-pager
```

The output contained records of commands executed under sudo, including:

- Starting Wazuh Manager.
- Starting Wazuh Indexer.
- Starting Wazuh Dashboard.
- Querying Wazuh version information.
- Checking the Manager service state.
- Inspecting `/var/log/secure`.
- Reviewing journald entries.
- Inspecting Wazuh log collection configuration.

Several of these commands were issued while the terminal was already operating in a root-UID context.

This is important because a sudo record generated from an existing root shell does not represent the same privilege transition as a non-root account obtaining root access.

## 5. Controlled Sudo Execution

A controlled test was performed using the non-root account.

The session was initiated with:

```bash
su - abhinavmathur
```

The account identity was verified:

```text
abhinavmathur
uid=1000(abhinavmathur) gid=1000(abhinavmathur) groups=1000(abhinavmathur),10(wheel)
```

The cached sudo authentication timestamp was cleared:

```bash
sudo -k
```

The following command was executed:

```bash
sudo /usr/bin/id
```

After authentication, the output returned:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### Interpretation

This was direct evidence that the non-root account successfully executed the selected command with root privileges.

The test demonstrated an authorized privilege elevation through sudo. It did not demonstrate exploitation, bypass of sudo authorization, or malicious activity.

## 6. Wazuh Alert Analysis

The Wazuh alerts file was reviewed:

`/var/ossec/logs/alerts/alerts.json`

The investigation examined sudo-related detection rules and related PAM session records.

### Rule ID 5402

The captured Wazuh Dashboard details showed:

| Attribute | Value |
|---|---|
| Rule ID | 5402 |
| Level | 3 |
| Description | Successful sudo to ROOT executed |
| Groups | syslog, sudo |
| MITRE ATT&CK ID | T1548.003 |
| Technique | Sudo and Sudo Caching |
| Tactics | Privilege Escalation, Defense Evasion |
| Fired Times | 16, as displayed in the captured alert details |
| Dashboard Timestamp | November 2, 2026, 07:43:40.265 |

The mapping to T1548.003 provides a useful classification for investigating potential abuse of sudo and its credential-caching behavior.

However, the detection alone does not establish malicious intent.

### PAM Session Events

The captured alert extraction included the following events:

| Timestamp (IST) | Rule ID | Description | Source User | Destination User |
|---|---:|---|---|---|
| 07:19:39.835 | 5501 | PAM login session opened | abhinavmathur | abhinavmathur (UID 1000) |
| 07:20:45.889 | 5501 | PAM login session opened | abhinavmathur | root (UID 0) |
| 07:20:57.891 | 5502 | PAM login session closed | Not reported | root |
| 07:20:57.891 | 5501 | PAM login session opened | abhinavmathur | root (UID 0) |

These events provided evidence of user and root session activity.

They were considered complementary authentication evidence rather than independent proof of malicious behavior.

## 7. Command Attribution Review

A detailed Rule ID 5402 alert record in the supplied output showed:

| Attribute | Value |
|---|---|
| Rule ID | 5402 |
| Rule Level | 3 |
| Agent | localhost.localdomain |
| Source User | root |
| Destination User | root |
| Command | `/bin/systemctl start wazuh-manager` |
| Location | journald |
| Timestamp | 2026-11-02 07:20:57.891 |

The corresponding journal entry showed:

```text
root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/systemctl start wazuh-manager
pam_unix(sudo:session): session opened for user root(uid=0) by abhinavmathur(uid=0)
```

The `abhinavmathur(uid=0)` detail indicates that the command was executed from a root-UID context.

This is consistent with the investigation's root shell being used for service administration. It should not be confused with the controlled test in which `abhinavmathur` had UID 1000 before executing `sudo /usr/bin/id`.

### Evidence Correlation Limitation

The controlled `/usr/bin/id` command clearly returned root identity. However, the available detailed Rule ID 5402 event identified a different command.

Therefore:

- Controlled sudo elevation was confirmed through command output.
- Rule ID 5402 was observed in Wazuh.
- PAM session activity involving the user and root was observed.
- The exact Rule ID 5402 event shown in detail was associated with the Wazuh Manager service-start command.
- A direct one-to-one correlation between the controlled `/usr/bin/id` execution and that particular Rule ID 5402 record was not established.

This limitation is retained to avoid attributing the wrong command to the detection.

## 8. Detection Query

The following single DQL query was used for reviewing sudo-related and PAM events in Wazuh Dashboard:

```text
rule.id: "5401" OR rule.id: "5402" OR rule.id: "5403" OR rule.id: "5404" OR rule.id: "5405" OR rule.id: "5406" OR rule.id: "5407" OR rule.id: "5501" OR rule.id: "5502"
```

The search was intended to cover:

- Successful sudo execution.
- Failed sudo attempts.
- Repeated authentication failures.
- Unauthorized sudo usage.
- Disallowed commands.
- PAM session activity.

The query was used with the `wazuh-alerts-*` index pattern.

## 9. Investigation Findings

| Investigation Area | Finding | Assessment |
|---|---|---|
| System baseline | Rocky Linux 9.8 and Wazuh 4.13.1 | Verified |
| Manager service | Active | Verified |
| User identity | abhinavmathur, UID 1000 | Verified |
| Administrative membership | Member of wheel | Verified |
| Sudo authorization | `(ALL) ALL` | Verified |
| Sudoers syntax | Parsed OK | Verified |
| Active NOPASSWD rule | Not identified in captured configuration | Verified within inspected output |
| Controlled privilege elevation | `/usr/bin/id` returned UID 0 | Verified |
| Authentication log file | `/var/log/secure` present | Verified |
| Journald collection block | Present in Wazuh configuration | Verified |
| Rule ID 5402 | Observed at level 3 | Verified |
| MITRE mapping | T1548.003 | Verified |
| PAM session activity | Rule IDs 5501 and 5502 observed | Verified |
| Exact `/usr/bin/id` alert correlation | Not established | Partially verified |
| Malicious privilege escalation | No evidence established | Not confirmed |
| Repeated failed sudo attempts | Not demonstrated in supplied evidence | Not tested |
| Unauthorized sudo usage | Not demonstrated | Not tested |
| Sudoers modification | No modification demonstrated | Not tested |

## 10. Conclusion

The investigation confirmed that the Linux account `abhinavmathur` was authorized to use sudo through membership in the `wheel` group. A controlled command executed from the non-root account returned root identity, demonstrating successful privilege elevation.

Wazuh provided visibility into sudo activity through Rule ID 5402 and PAM session detections. The MITRE ATT&CK mapping identified the relevant technique as T1548.003.

The investigation also demonstrated why alert attribution must be validated using original event details. A captured Rule ID 5402 record described a root-to-root service-start operation rather than the controlled `/usr/bin/id` command.

The findings support successful sudo monitoring and privileged activity investigation. They do not establish unauthorized access, exploitation, or malicious privilege escalation.
