## Admin Search Audit Events Index - API Keys Activity

```
(_index=sumologic_audit_events _sourcecategory=accessKeys)

// https://help.sumologic.com/Manage/Security/Audit_Event_Index
// https://service.us2.sumologic.com/audit/docs/#operation/getTransformationRuleDeleted

// | where !(EventName contains "LoggedIn" or EventName contains "LoggedOut" or EventName contains "TimedOut")
| json field=_raw "eventName" as EventName nodrop
// | where EventName contains "ContentAsynchronousExportRequested"
// | where _sourceCategory contains "collect" or _sourceCategory=monitorLibrary or _sourceCategory=roles or _sourceCategory=passwordPolicy or _sourceCategory=scheduledView 
| json field=_raw "operator.email" as SumoLogicOperator nodrop
| json field=_raw "operator.sourceIp" as SumoLogicOperatorIP nodrop
| json field=_raw "operator.interface" as SumoLogicInterface nodrop
| concat (SumoLogicOperator, "-", SumoLogicOperatorIP) as <company>Admin 
//| json field=_raw "contentIdentity.type" as ContentIdentity nodrop
//| json field=_raw "contentIdentity.name" as IdentityName nodrop
| count by _messagetime,_sourceCategory,EventName,<company>Admin,SumoLogicInterface
| sort by _sourceCategory asc
```

## Admin Search Audit Events Index - Collector Activity

```
(_index=sumologic_audit_events _sourcecategory=collection)

// https://help.sumologic.com/Manage/Security/Audit_Event_Index
// https://service.us2.sumologic.com/audit/docs/#operation/getTransformationRuleDeleted

// | where !(EventName contains "LoggedIn" or EventName contains "LoggedOut" or EventName contains "TimedOut")
| json field=_raw "eventName" as EventName nodrop
| where !(EventName contains "CollectorUpgrade") | where !(EventName contains "SourceUpdated") | where !(EventName contains "EphemeralCollectorDeleted")
| json field=_raw "collectorIdentity.collectorName" as CollectorName nodrop
| where !(CollectorName contains "vault-")
| json field=_raw "operator.email" as SumoLogicOperator nodrop
| json field=_raw "operator.sourceIp" as SumoLogicOperatorIP nodrop
| json field=_raw "operator.interface" as SumoLogicInterface nodrop
| concat (SumoLogicOperator, " -", SumoLogicOperatorIP) as <company>Admin 
| count by _messagetime,_sourceCategory,EventName,CollectorName,<company>Admin
| sort by _messagetime
```

## Admin Search Audit Events Index - User Roles Activity

```
(_index=sumologic_audit_events _sourcecategory=roles)

// https://help.sumologic.com/Manage/Security/Audit_Event_Index
// https://service.us2.sumologic.com/audit/docs/#operation/getTransformationRuleDeleted

// | where !(EventName contains "LoggedIn" or EventName contains "LoggedOut" or EventName contains "TimedOut")
| json field=_raw "eventName" as EventName nodrop
// | where EventName contains "ContentAsynchronousExportRequested"
// | where _sourceCategory contains "collect" or _sourceCategory=monitorLibrary or _sourceCategory=roles or _sourceCategory=passwordPolicy or _sourceCategory=scheduledView 
| json field=_raw "operator.email" as SumoLogicOperator nodrop
| json field=_raw "operator.sourceIp" as SumoLogicOperatorIP nodrop
| json field=_raw "operator.interface" as SumoLogicInterface nodrop
| concat (SumoLogicOperator, "-", SumoLogicOperatorIP) as <company>Admin 
| count by _messagetime,_sourceCategory,EventName,<company>Admin,SumoLogicInterface
| sort by _sourceCategory asc
```

## Admin Search Audit Events Index - Users Account Activity

```
(_index=sumologic_audit_events _sourcecategory=users)

// https://help.sumologic.com/Manage/Security/Audit_Event_Index
// https://service.us2.sumologic.com/audit/docs/#operation/getTransformationRuleDeleted

// | where !(EventName contains "LoggedIn" or EventName contains "LoggedOut" or EventName contains "TimedOut")
| json field=_raw "eventName" as EventName nodrop
// | where EventName contains "ContentAsynchronousExportRequested"
// | where _sourceCategory contains "collect" or _sourceCategory=monitorLibrary or _sourceCategory=roles or _sourceCategory=passwordPolicy or _sourceCategory=scheduledView 
| json field=_raw "operator.email" as SumoLogicOperator nodrop
| json field=_raw "operator.sourceIp" as SumoLogicOperatorIP nodrop
| json field=_raw "operator.interface" as SumoLogicInterface nodrop
| concat (SumoLogicOperator, "-", SumoLogicOperatorIP) as <company>Admin 
| json field=_raw "rolesAdded[0].roleName" as RolesAdded nodrop
| json field=_raw "userIdentity.userEmail" as <company>User nodrop
| concat (<company>User, "-", RolesAdded) as <company>User_Plus_Role 
| count by _messagetime,_sourceCategory,EventName,<company>Admin,<company>User_Plus_Role
| sort by _messagetime
```
