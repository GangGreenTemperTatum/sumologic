## G-Suite Phishing-related - Alert Center Alerts

```
_source = "GoogleSuiteAlerts"  recipient "Gmail phishing"
| json "alertId","customerId","source","type","data" as alert_id, customer_id, source, type, data
| where source = "Gmail phishing"
| json field=data "messages[*]", "maliciousEntity.fromHeader"  as messages, attacker
// | toURL(concat("https://admin.google.com/ac/ac/alert/details?alertId=", alert_id), alert_id) as alert_id
| parse regex field=messages "(?<message_info>\{[^\{]+\})" multi 
| json field=message_info "date", "subjectText", "recipient", "messageBodySnippet" as message_date, subject, victim, message_body_snippet nodrop
| count by message_date, alert_id, attacker, victim, type, subject, message_body_snippet
| sort by attacker,message_date 
| fields -_count
// | transpose row type column victim```
```

## G-Suite Google Environment - Alert Center Alerts

```
_sourceCategory="google-services"
| json field=_raw "alertId" as AlertID
| "https://admin.google.com/ac/ac/alert/details?alertId=" as F1
| concat (F1,AlertID) as Investigate
| tourl (Investigate,"CLICK HERE - Investigation Link") as Investigate
| fields -F1,AlertID
| json field=_raw "metadata.severity" as Alert_Severity
| json field=_raw "source" as Alert_Source
//| where Alert_Source contains "Mobile device management"
| json field=_raw "type" as Alert_Type
| json field=_raw "source" as Source nodrop
| json field=_raw "data.email" as Affected_User nodrop 
| json field=_raw "data.messages[*].recipient" as Email_Victim nodrop

| count by Alert_Severity,Alert_Source,Alert_Type,Affected_User,Email_Victim,Investigate
```

## G-Suite Google Environment - Security Center Rule Triggers

```
_sourceCategory="google-services"
| json field=_raw "events[0].name" as G_Sec_Center_Event
| where G_Sec_Center_Event = "SECURITY_CENTER_RULE_THRESHOLD_TRIGGER"
| json field=_raw "events[0].parameters[0].value" as Alert_Name

| "https://admin.google.com/ac/ac" as F1
| concat (F1,"Investigate") as Investigate
| tourl (Investigate,"CLICK HERE - Investigation Link") as Investigate
| fields -F1
| count G_Sec_Center_Event, Alert_Name, Investigate
```
