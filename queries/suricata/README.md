* My [Suricata](https://suricata.io) logs are shipped to a Sumo Logic Hosted Endpoint Collector using [FluentD](https://docs.fluentd.org/) via [Rsyslog](https://www.rsyslog.com/)

## Parsing generic Suricata `fast.log` signature matches:

```
(_sourceCategory="suricata-ids")
//| parse regex "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
//| parse "[\t:*:2]" as RuleID nodrop
//| parse regex "(?<RuleIDs>\[([1-9]|):\d{1,7}:([1-9]|)\])"
//| parse regex field=RuleID "(\[([1-9]|):\d{1,7}:([1-9]|)\])" multi
| parse "} *:* -> *:*\"}" as SrcIP,SrcPort,DstIP,DstPort nodrop
| parse "[Priority: *] {*}" as Priority,Protocol nodrop
| parse "[Classification: *]" as RuleClassification nodrop
| parse "] * (*) [" as Rule_Description,Rule_Comments nodrop
| parse "{\"message\":\"*-*.*  [" as Date,Time,MS nodrop
| fields -MS,Date,Time // Use _messageTime Sumo default field

//| count SrcIP,SrcPort,DstIP,DstPort,Protocol,Priority,RuleID,RuleDescription,RuleClassification
//| sort by Priority,_count
```
