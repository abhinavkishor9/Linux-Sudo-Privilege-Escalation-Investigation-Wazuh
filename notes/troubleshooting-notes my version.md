# Troubleshooting Notes 

## 1. Distinguishing Root Shell Commands from Non-Root Sudo Elevation

### Observation

The initial terminal prompt showed:

```text
[root@localhost ~]#
```

Several administrative commands were executed from this root shell using `sudo`, including:

```bash
sudo systemctl start wazuh-manager
sudo systemctl start wazuh-indexer
sudo systemctl start wazuh-dashboard
```

The journal recorded entries such as:

```text
root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/systemctl start wazuh-manager
```

It also showed:

```text
pam_unix(sudo:session): session opened for user root(uid=0) by abhinavmathur(uid=0)
```

### Explanation

These commands were issued from a root-UID context. Using `sudo` from an already-root shell does not demonstrate a normal non-root-to-root privilege transition.

This distinction matters when interpreting Rule ID 5402 alerts.

### Resolution

A separate controlled test was performed by switching to `abhinavmathur`:

```bash
su - abhinavmathur
```

The account identity was verified as UID 1000 before executing:

```bash
sudo -k
sudo /usr/bin/id
```

The command returned UID 0.

**Lesson:** Always record the identity before and after privilege elevation. Do not interpret every sudo log entry as evidence of a regular user obtaining root privileges.

---

## 2. Understanding the Wheel Group

### Observation

The group membership check returned:

```text
wheel:x:10:abhinavmathur
```

The account identity showed:

```text
uid=1000(abhinavmathur) gid=1000(abhinavmathur) groups=1000(abhinavmathur),10(wheel)
```

### Explanation

The `wheel` group is used in this Linux environment to grant administrative sudo permissions through the sudoers configuration.

The presence of an account in this group indicates that it may have administrative privileges, depending on the effective sudoers rules.

### Verification

```bash
getent group wheel
id abhinavmathur
sudo -l -U abhinavmathur
```

The permission listing confirmed:

```text
User abhinavmathur may run the following commands on localhost:
    (ALL) ALL
```

**Lesson:** Group membership alone is not enough to establish effective permissions. Review the sudoers configuration and the account's actual allowed commands.

---

## 3. Understanding the NOPASSWD Configuration

### Observation

The sudoers file contained:

```text
%wheel  ALL=(ALL)       ALL
```

The following example was commented out:

```text
# %wheel        ALL = (ALL)       NOPASSWD: ALL
```

### Explanation

The active rule permits members of `wheel` to execute all commands through sudo. The commented example does not grant passwordless sudo access.

The controlled test explicitly cleared the cached authentication timestamp:

```bash
sudo -k
```

The subsequent command displayed a password prompt.

### Validation

```bash
sudo visudo -c
```

Returned:

```text
/etc/sudoers: parsed OK
```

**Lesson:** Do not interpret a commented `NOPASSWD` example as an active security weakness. Examine the effective configuration.

---

## 4. Authentication Events and Log Source Identification

### Observation

The system contained:

```text
/var/log/secure
```

The file listing showed:

```text
-rw-------. 1 root root 17K Nov  2 07:26 /var/log/secure
```

The Wazuh Manager configuration also contained an existing journald collection block:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```

### Explanation

The investigation used systemd journal records to examine sudo activity.

The command:

```bash
sudo journalctl _COMM=sudo --since "30 minutes ago" --no-pager
```

returned sudo commands and PAM session messages.

The presence of `/var/log/secure` does not by itself establish that Wazuh was collecting that file directly. The captured alert records identified `journald` as their source location.

### Resolution

The existing journald collection configuration was used for the investigation. No duplicate authentication log collection block was added.

**Lesson:** Identify the active log source before changing Wazuh collection settings.

---

## 5. Understanding Rule ID 5402

### Observation

Wazuh reported:

```text
Rule ID: 5402
Rule Level: 3
Description: Successful sudo to ROOT executed.
```

The Dashboard also showed:

```text
rule.mitre.id: T1548.003
rule.mitre.technique: Sudo and Sudo Caching
rule.mitre.tactic: Privilege Escalation, Defense Evasion
```

### Explanation

Rule ID 5402 identifies successful sudo execution as root.

The MITRE ATT&CK mapping associates the behavior with T1548.003.

However, the rule is a detection of privileged activity, not a verdict that the activity was malicious.

### Resolution

Validate the alert using:

- Source user.
- Destination user.
- Executed command.
- Terminal and working directory.
- Timestamp.
- Relevant PAM session records.
- Account authorization and expected administrative activity.

**Lesson:** A successful sudo alert should trigger context-based investigation, not automatic incident classification.

---

## 6. PAM Session Events Without Command Details

### Observation

The investigation identified:

- Rule ID 5501 — PAM login session opened.
- Rule ID 5502 — PAM login session closed.

Some captured records did not contain a command field.

### Explanation

PAM session records provide evidence of session activity. They do not necessarily contain the command associated with a sudo operation.

A PAM session event should therefore be correlated with sudo command records and other relevant activity.

### Resolution

Use timestamps, source user, destination user, and host identity to correlate the records.

Avoid treating a session-open or session-close event as proof that a particular administrative command was executed.

**Lesson:** Authentication events and command-execution records provide different types of evidence.

---

## 7. Rule ID 5402 Command Attribution Discrepancy

### Observation

The captured detailed Rule ID 5402 event showed:

```text
Source User: root
Destination User: root
Command: /bin/systemctl start wazuh-manager
```

However, the controlled test was:

```bash
sudo /usr/bin/id
```

executed from the `abhinavmathur` account.

### Explanation

The detailed Rule ID 5402 event corresponded to a different command from the controlled test.

The underlying journal record also indicated that the service-start command was executed from a root-UID context.

### Resolution

Keep the two observations separate:

1. The controlled `/usr/bin/id` command returned UID 0, confirming successful privilege elevation.
2. The detailed Rule ID 5402 alert identified a root-to-root service-start command.

A direct one-to-one correlation between the controlled test and the displayed Rule ID 5402 record was not established.

**Lesson:** Never associate an alert with a test action solely because both involve sudo. Match the actual command and event timestamp.

---

## 8. Dashboard Query and Alert Visibility

### Query

The following DQL query can be used to review sudo-related and PAM events:

```text
rule.id: "5401" OR rule.id: "5402" OR rule.id: "5403" OR rule.id: "5404" OR rule.id: "5405" OR rule.id: "5406" OR rule.id: "5407" OR rule.id: "5501" OR rule.id: "5502"
```

### Search Settings

- Index pattern: `wazuh-alerts-*`
- Time range: Include the actual lab activity.
- Relevant fields: `rule.id`, `rule.level`, `agent.name`, `data.srcuser`, `data.dstuser`, `data.command`, and `timestamp`.

### Interpretation

The query retrieves several sudo-related and PAM detections. It does not establish that all returned records are associated with the same user session or controlled test.

Correlate each result individually.

---

## 9. Failed Sudo Activity Not Demonstrated

### Observation

The supplied evidence confirms successful sudo activity and related PAM events.

It does not provide a confirmed failed sudo authentication event or unauthorized sudo attempt.

### Explanation

Rules associated with failed authentication or unauthorized sudo usage should not be reported as triggered unless a matching alert is available.

### Resolution

Record failed sudo attempts and unauthorized sudo usage as untested in this exercise.

Do not invent failed attempts or describe the controlled successful test as a failed authentication investigation.

---

