* My [Acunetix](https://online.acunetix.com/) logs are shipped to a Sumo Logic Hosted Endpoint Collector using [FluentD](https://docs.fluentd.org/)

## Actunetix High Severity Scan Result

```
(_sourcecategory="acunetix")
| parse "{\"affects_detail\": \"\", \"affects_url\": \"xxx.xxx.xxx.xxx:YYYY/tcp\", \"app\": *, \"archived\": false, \"confidence\": 0, \"continuous\": true, \"criticality\": *, \"issue_id\": null, \"last_seen\": \"2021-09-13T04:13:44.067928-07:00\", \"severity\": \"*\", \"status\": \"*\", \"tags\": *, \"target_description\": \"<COMPANY> API\", \"target_id\": \"91cf58de-4401-431c-96ae-0d82b48456e2\", \"vt_created\": null, \"vt_id\": \"*\", \"vt_name\": \"*\", \"vt_updated\": null, \"vuln_id\": \"2653271852788484076\"}" as Application,Criticality_Score,Severity,Status,Tags,VT_ID,VT_Name
| where contains(Severity,"high")
| timeslice 1d
| count by Severity, Target_Description, Application, Criticality_Score, Status, Tags
| sort by Severity
| transpose row Status,Target_Description, Application, Criticality_Score, Tags column Severity

// The above filter expression parses logs from Acunetix scanner for HIGH serverity results
// It parses information and creates fields to summarize the threat and severity
```

## Acunetix Overall Closed Scan Vulnerability Reports

```
(_sourcecategory="acunetix")
| parse "\"vuln_id\": \"*\"" as Vulnerability_ID
| parse "\"affects_url\": \"*\"" as URL
| parse "\"app\": \"*\"" as Application
| parse "\"severity\": \"*\"" as Severity
| parse "\"status\": \"*\"," as Status
| where Status contains "closed" or Status contains "Closed"

| parse "\"criticality\": *," as Criticality_Score
// as Application,Criticality_Score,Severity,Status,Tags,VT_ID,VT_Name
| parse "\"vt_name\": \"*\"" as VT_Name
| parse "\"tags\": [\"*\"]" as Tags

// Removing DUP - In this case, the vuln_id of a vulnerability is unique but multiple logs may be generated and may also appear in multiple reports
// Therefore, we do not want to duplicate these logs and therefore incorrectly calculate the number of vulnerabilities

| 1 as rank // Creating a new field called rank
| accum rank by Vulnerability_ID,URL,Application // Accumulating the new field of rank to identify duplicitive fields - I.E 1, 2, 3 per each individual log... The Primary Key is created from the BY statement and I also included URL as this same vulnerability could display for different Applications
// | where Vulnerability_ID = 2613308093345301818 // Use this to illustrate I have four individual logs that are the same (_accum) that belong to the same Vulnerability_ID (also check the timestamps)
// Could even SORT BY _accum to show the amount of duplications
// | sort by _accum
| where _accum = 1 // Therefore only including accum field value = 1 (unique value) and greater than 1 equals duplicitive value from the above

// | count by Severity, Target_Description, Application, Criticality_Score, Status, Tags
| fields -_accum // Remove the "_accum" field as no longer required and not wanting to omit in a report
| fields -rank // Remove the "rank" field as no longer required and not wanting to omit in a report

| target_description as Platform
| count by Severity, Platform
// | transpose row Status,Target_Description, Application, Criticality_Score, Tags column Severity

// The above filter expression parses logs from Acunetix scanner for ANY serverity results
// It parses information and creates fields to summarize the threat and severity
```
