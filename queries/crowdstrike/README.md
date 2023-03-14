## CrowdStrike EDR - Aggregate Log Event Types

```
(_sourcecategory="crowdstrike")
| parse "\"eventType\":\"*\"," as Event_Type
| count Event_Type
```

## CrowdStrike EDR - Malicious Commands Executed on Machines

```
(_sourcecategory="crowdstrike" "The commands executed on this CLI are suspicious")
| parse "\"ComputerName\":\"*\"" as ComputerName
| parse "\"UserName\":\"*\"," as Username
| parse "\"SeverityName\":\"*\"," as SeverityName
| parse "\"Severity\":*," as SeverityLevel
| where SeverityLevel >= 4
| parse "\"FilePath\":\"*\"," as Filepath
| parse "\"FileName\":\"*\"," as FileName
| count by _count, ComputerName, Username, SeverityName, SeverityLevel, FileName, Filepath
| sort by _count
| transpose row ComputerName, Username, SeverityName, SeverityLevel, FileName, Filepath column _count
```

## CrowdStrike EDR - IoC

```
(_sourcecategory="crowdstrike" "Custom Intelligence Indicator (Custom IOC)."))
| parse "\"ComputerName\":\"*\"" as ComputerName
| parse "\"UserName\":\"*\"," as Username
| parse "\"SeverityName\":\"*\"," as SeverityName
| parse "\"Severity\":*," as SeverityLevel
| where SeverityLevel >= 2
| parse "\"FilePath\":\"*\"," as Filepath
| parse "\"FileName\":\"*\"," as FileName
| count by _count, ComputerName, Username, SeverityName, SeverityLevel, FileName, Filepath
| sort by _count
| transpose row ComputerName, Username, SeverityName, SeverityLevel, FileName, Filepath column _count
```

## CrowdStrike EDR - Top Users and Installed Applications

```
(_sourcecategory="crowdstrike")
| parse "\"FileName\":\"Install *\"" as Installed_File
| parse "\"UserName\":\"*\"" as Username
| parse "\"SeverityName\":\"*\"," as Severity_Level
| parse "\"Severity\":*," as Severity_Number
| where Severity_Number > "3"
| sort by Severity_Number
| count by Username, Installed_File, Severity_Level, Severity_Number
// | transpose row Username, Installed_File, Severity_Level, Severity_Number column _count
```

## CrowdStrike EDR - Sensor Failed Detection to Hosts from Falcon

```
_sourceCategory="crowdstrike" "sensor"
| json field=_raw "event.ServiceName" as SUP
| where SUP != "sensor_update_policy"
```

```
_sourceCategory="crowdstrike"
| json field=_raw "event.HostnameField" as Hostname
| where Hostname == "localhost"
| json field=_raw "metadata.eventType" as Event_Type
| json field=_raw "event.Commands" as Commands_Ran
| count by Hostname,Event_Type,Commands_Ran
```

## CrowdStrike EDR - Total Identified Malware Aggregate

```
(_sourcecategory="crowdstrike")
| parse "\"eventType\":\"*\"" as Event_type
| where Event_Type contains "Detection" or Event_Type contains "detection"
| parse "\"DetectDescription\":\"*\"" as Detection_Description
| where Detection_Description contains "malware" or Detection_Description contains "adware" or Detection_Description contains "AV" or Detection_Description contains "virus" or Detection_Description contains "malicious"
| parse "\"FileName\":\"*\"" as Malware_Filename
| parse "\"FilePath\":\"/*\"" as FilePath
| parse "\"DetectName\":\"*\"" as Detection_Mechanism
| parse "\"UserName\":\"*\"" as Username
| parse "\"SeverityName\":\"*\"," as Severity_Level
| parse "\"Severity\":*," as Severity_Number
| toint(Severity_Number) as Severity_Number // - Amend the datatype from a string to an integer for numerical fields to apply appropriate Sort by Severity
| parse "\"PatternDispositionDescription\":\"*\"" as Pattern_Disposition

| count by Severity_Level, Severity_Number, Username, Malware_Filename, FilePath, Detection_Mechanism
| fields -_count // Remove the "_count" field
| sort by Severity_Number desc
```
