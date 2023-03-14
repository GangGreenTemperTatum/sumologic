## Wazuh IDS Alerts generic parse from native log

```
_source="WazuhAlerts"
// Wazuh cluster follows NIST 800-53 Risk Management Framework RMF / PCI DSS  / GPG13 / GDPR and HIPAA regs
| json field=_raw "rule.level" as Wazuh_Rule_Level
// Include a WHERE statement to drop logs with a severity less-then 5 considered non-risk
| where Wazuh_Rule_Level > 5
// Before the IF statements, sort by the level integer by highest first
| sort by Wazuh_Rule_Level

// Take the Wazuh_Level_Severity integer's and classify each as string values with their corresponding Rule Level Titles

| if(Wazuh_Rule_Level=0,"Ignored", 
 if(Wazuh_Rule_Level=2,"System low priority notification", 
 if(Wazuh_Rule_Level=3,"Successful/Authorized events" , 
 if(Wazuh_Rule_Level=4,"System low priority error", 
 if(Wazuh_Rule_Level=5,"User generated error", 
 if(Wazuh_Rule_Level=6,"Low relevance attack", 
 if(Wazuh_Rule_Level=7,"Bad word matching", 
 if(Wazuh_Rule_Level=8,"First time seen", 
 if(Wazuh_Rule_Level=9,"Error from invalid source", 
 if(Wazuh_Rule_Level=10,"Multiple user generated errors", 
 if(Wazuh_Rule_Level=11,"Integrity checking warning", 
 if(Wazuh_Rule_Level=12,"High importance event", 
 if(Wazuh_Rule_Level=13,"Unusual error (high importance)", 
 if(Wazuh_Rule_Level=14,"High importance security event", 
 if(Wazuh_Rule_Level=15,"Severe attack","None"))))))))))))))) as Wazuh_Rule_Title

// The "none" represents ELSE statement, value of false which is when there is no match to any of the above scenarios. However, in our case the Wazuh IPS/IDS server will always present a value defined for this field as a classification - https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html

| json field=_raw "rule.description" as IDS_Detection
| json field=_raw "rule.mitre.id" as Mitre_Attack_ID
| json field=_raw "rule.mitre.tactic" as Mitre_Tactic
| json field=_raw "rule.mitre.technique" as Mitre_Attack_Technique
| json field=_raw "agent.name" as Host

| count by Wazuh_Rule_Level,Wazuh_Rule_Title
```
