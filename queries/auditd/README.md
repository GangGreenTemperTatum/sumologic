* My [AuditD](https://linux.die.net/man/8/auditd) logs are shipped to a Sumo Logic Hosted Endpoint Collector using [FluentD](https://docs.fluentd.org/)

## Parse AuditD Keys Used

```
_sourceName=auditd | parse "key=\"*\"" as key | count by key | sort _count
```

## Interpret Commands Ran by User Actions

```
_sourceName=auditd
| parse "UID=\"*\"" as uid
| where uid !="root"
| parse "exe=\"*\"" as exe
| parse "ses=* " as session_id
| parse "msg=audit(*)" as audit_tag
| where session_id matches "*" | count by exe,uid,audit_tag
```

## AuditD Protctitle

```
// _sourceName=auditd "saddr" | parse "laddr=* " as ip | where !isPrivateIp(ip) | count by ip | sort _count
// _sourceName=auditd | parse "laddr=* " as ip | where !isPrivateIp(ip) | count by ip | sort _count
_sourceName=auditd | parse "laddr=* " as ip | where !isPrivateIp(ip) | count by ip | sort _count
// type=PROCTITLE
```

## AuditD Summary of Commands (SYSCALL) Ran by User

```
((_sourcename="/var/log/audit/audit.log"))
| parse "type=* " as Type
| where type = "SYSCALL"
| parse "comm=* " as Command
| parse "UID=\"*\"" as UserID
| timeslice 1d 
| count by Command, UserID
| sort by _count
// The above filter displays all logs from AuditD Linux Kernel but parses the Type of logs == SYSCALL which is defined as a System Call
// It then churns out the results and sorts by count (highest>lowest) against the command ran
```

## AuditD Decode Ran Processes and Commands

```
_sourceName=auditd
| parse "type=* " as type
//| count by type
| where type = "PROCTITLE"
| parse "proctitle=*" as proc 
//| hexToAscii(proc) as dec 
| replace(proc, /[0]{2,}/, "20") as proc // Hex edit replace null with space
| hexToAscii(proc) as cmd | count cmd | sort _count
```
