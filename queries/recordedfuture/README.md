## Threat Intel - Remote IP Addresses by Risk Rule Parsed by Historic or Current Risk Rules Triggered

```
_source="security/recordedfuture"
| json field=_raw "source" as Target
| json field=_raw "ip_address" as Remote_IP
| json field=_raw "data.risk.criticality" as Criticality_Rating
| json field=_raw "data.risk.riskString" as Risk_Rules_Matched
| json field=_raw "data.risk.score" as Risk_Score
| json field=_raw "data.risk.criticalityLabel" as Criticality_Verdict
| json field=_raw "data" as Intel_Data

| json field=Intel_Data "risk.evidenceDetails..rule" as Risk_Rules_Detected
// Above statement can also be written as:
// | json field=Intel_Data "risk.evidenceDetails[*]rule" as Risk_Rules_Detected
| parse regex field = Risk_Rules_Detected "\"(?<rule>.*?)\"" multi
| if (rule matches "Historical*","Historical_Rule","Recent_Rule") as Rule_Category

// | format("%s : %s","Five Minute Rate is :" , rate) as formattedVal

// | where Risk_Rules_Detected contains "hist" 
// | fields Risk_Rules_Detected as Historic_Risk_Rules_Detected

| json field=Intel_Data "risk.evidenceDetails.[*].criticalityLabel" as Criticality_of_Risk_Rule
// | fields -Intel_Data
// Whilst prepping the aggregate, use fields to hard-code the Messages fields - Must after agg statement
| fields Target,Remote_IP,Criticality_Rating,Risk_Rules_Matched,Risk_Rules_Detected,Rule,Rule_Category,Criticality_of_Risk_Rule
| count (Rule_Category) by Remote_IP,Rule_Category
| transpose row Remote_IP column Rule_Category
//by Target,Remote_IP,Criticality_Rating,Risk_Rules_Matched,Risk_Rules_Detected,Criticality_of_Risk_Rule
```
