* My [HackerOne](https://hackerone.com) logs are shipped to a Sumo Logic Hosted Endpoint Collector using [FluentD](https://docs.fluentd.org/)

## All Bug Bounties Paid in The Last 30 Days

```
(_source="hackerone")
| parse "\"bounty_awarded_at\": \"*\"" as Bounty_Awarded
| where Bounty_Awarded != "null" // - For testing
// | where Bounty_Awarded = "Null" OR Bounty_Awarded = "null"
| parse "\"type\": \"*\"" as Type
| where Type = "report"
| parse "\"vulnerability_information\": \"*\"" as Vuln_Info
| parse "\"id\": \"*\"" as ID
// | where ID = X
| parse "\"title\": \"*\"" as Title
| parse "\"state\": \"*\"" as Status
| parse "\"external_id\": \"*\"" as External_ID
| count Bounty_Awarded, Status, ID, Title, External_ID, Type, Vuln_Info
| fields -_count // Remove the "_count" field
| sort by Bounty_Awarded
// | toint(Bounty_Awarded) as Date_Bounty_Awarded // - Amend the datatype from a string to an integer for numerical fields
// | sort by Date_Bounty_Awarded desc
// | transpose row Bounty_Awarded, Status, ID, Title, External_ID, Type, Vuln_Info column Title

// WHERE statement that states where the Bounty_Awarded field within the message equals a null representative (case)
// | where Bounty_Awarded in ("Null","null") 
```

## All Bug Bounties Paid Detailed

```
((((_source="hackerone"))))
| parse "\"awarded_currency\": \"*\"" as Award_Currency
| parse "\"awarded_bonus_amount\": \"*\"" as Award_Bonus
| where Award_Bonus >= "0.00"
| num(Award_Bonus) // - Amend the datatype from a string to an integer for numerical fields
// WHERE statement does not use != as data format of value is an integer
| parse "\"awarded_amount\": \"*\"" as Award_Value
| where Award_Value > "0.00"
| num(Award_Value) // - Amend the datatype from a string to an integer for numerical fields
// WHERE statement does not use != as data format of value is an integer
// | toInt(Award_Value) as Award_Value_Int // - Amend the datatype from a string to an integer for numerical fields
| parse "\"bounty_awarded_at\": \"*\"" as Bounty_Awarded
| where Bounty_Awarded != "null" // - For testing
| parse "\"type\": \"*\"" as Type
// | where Type = "report"
// | parse "\"vulnerability_information\": \"*\"" as Vuln_Info
| parse "\"id\": \"*\"" as ID
// | parse "\"title\": \"*\"" as Title
// | parse "\"state\": \"*\"" as Status
// | parse "\"external_id\": \"*\"" as External_ID 

// Calculate the Total Value of Award Value, Calculate the Total Value of Award_Bonus
// Add the two results to a Total Reward Value
// | sum(Award_Value) as Award_Value_Tot, sum(Award_Bonus) as Award_Bonus_Tot
// | OR:
| count as Reports, sum(Award_Value) as Award_Value_Tot, sum(Award_Bonus) as Award_Bonus_Tot
| Award_Value_Tot + Award_Bonus_Tot as Total_Award

// | avg(Total_Award) as Average_Paid by Reports
```

## Open Cases Tracker

```
((((((_source="hackerone"))))))
| parse "\"type\": \"*\"" as Type
| where Type = "report"
| parse "\"vulnerability_information\": \"*\"" as Vuln_Info
| parse "\"id\": \"*\"" as ID
// | where ID = X
| parse "\"title\": \"*\"" as Title
| parse "\"state\": \"*\"" as Status
| where Status != "resolved"
| where Status != "duplicate"
| where Status != "not-applicable"
// | where contains(Status,"Open")
| parse "\"external_id\": \"*\"" as External_ID
| sort by Status
| count by Status, ID, Title, External_ID, Type, Vuln_Info
// | transpose row _count, status column status

// The above filter gathers logs from HackerOne Reports and parses the Report aspect of the Type field to display BPP reports that do not equal the value of Resolved/DUP/NA and therefore open 
```

## Paid Cases Tracker

```
(_source="hackerone")
| parse "\"type\": \"*\"" as Type
| where Type = "report"
| parse "\"vulnerability_information\": \"*\"" as Vuln_Info
| parse "\"id\": \"*\"" as ID
// | where ID = X
| parse "\"title\": \"*\"" as Title
| parse "\"state\": \"*\"" as Status
| where Status != "resolved"
| where Status != "duplicate"
| where Status != "not-applicable"
// | where contains(Status,"Open")
| parse "\"external_id\": \"*\"" as External_ID
| sort by Status
| count by Status, ID, Title, External_ID, Type, Vuln_Info
// | transpose row _count, status column status
 
// The above filter gathers logs from HackerOne Reports and parses the Report aspect of the Type field to display BPP reports that do not equal the value of Resolved/DUP/NA and therefore open 
```
