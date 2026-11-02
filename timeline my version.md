# Lab Timeline

## 2026-11-02 — Investigation Timeline

All timestamps are in IST (UTC+05:30).

### System Baseline and User Authorization

| Time | Activity / Observation | Result |
|---|---|---|
| Time not recorded | Inspected Rocky Linux operating system and host information. | Rocky Linux 9.8 identified |
| Time not recorded | Checked Wazuh version and Manager service status. | Wazuh 4.13.1; Manager active |
| Time not recorded | Identified regular Linux account `abhinavmathur`. | UID 1000 |
| Time not recorded | Inspected administrative group membership. | Account found in `wheel` |
| Time not recorded | Reviewed effective sudo permissions. | `(ALL) ALL` permission reported |
| Time not recorded | Validated sudoers configuration using `visudo -c`. | Parsed OK |
| Time not recorded | Inspected `/var/log/secure` and journald collection configuration. | File present; journald collection block identified |

### Controlled Privilege Elevation

| Time | Activity / Observation | Result |
|---|---|---|
| Time not recorded | Switched from root to `abhinavmathur`. | Non-root account session established |
| Time not recorded | Verified account identity using `whoami` and `id`. | UID 1000 confirmed |
| Time not recorded | Cleared cached sudo authentication timestamp using `sudo -k`. | Fresh authentication required |
| Time not recorded | Executed `sudo /usr/bin/id`. | Command completed successfully |
| Time not recorded | Examined command output. | UID 0 (root) returned |

The exact execution timestamp of the controlled `/usr/bin/id` command was not captured in the supplied evidence.

### Authentication and PAM Event Review

| Time (IST) | Activity / Observation | Result |
|---|---|---|
| 07:19:39.835 | Wazuh reported PAM session opened for `abhinavmathur`. | Rule ID 5501 |
| 07:20:45.889 | Wazuh reported PAM session opened for `root`, with `abhinavmathur` as the source user. | Rule ID 5501 |
| 07:20:57.891 | Wazuh reported a PAM session closed for root. | Rule ID 5502 |
| 07:20:57.891 | Wazuh reported another PAM session opened for root. | Rule ID 5501 |

### Sudo Command Log Review

| Time (IST) | Activity / Observation | Result |
|---|---|---|
| 07:20:57 | Journal recorded `sudo systemctl start wazuh-manager`. | Root-to-root command context |
| 07:21:06 | Journal recorded `sudo systemctl start wazuh-indexer`. | Root-to-root command context |
| 07:21:17 | Journal recorded `sudo systemctl start wazuh-dashboard`. | Root-to-root command context |
| 07:26:49 | Journal recorded Wazuh version inspection. | Administrative command recorded |
| 07:26:49 | Journal recorded Manager service-state inspection. | Administrative command recorded |
| 07:30:05 | Inspected `/var/log/secure`. | File size reported as 17 KB |
| 07:30:19 | Queried recent sudo journal records. | Authentication records reviewed |
| 07:30:36 | Inspected Wazuh log collection configuration. | Journald collection block identified |
| 07:32:03 | Searched `/var/log/secure` for sudo records. | Command executed; no specific extracted matching records documented |

### Wazuh Detection Review

| Time (IST) | Activity / Observation | Result |
|---|---|---|
| 07:20:57.891 | Detailed Rule ID 5402 record identified `/bin/systemctl start wazuh-manager`. | Source and destination user both shown as root |
| 07:43:40.265 | Captured Wazuh Dashboard Rule ID 5402 details. | Level 3; MITRE T1548.003 |
| 07:43:40.265 | Dashboard details displayed `rule.firedtimes` as 16. | Reported firing count in captured view |

