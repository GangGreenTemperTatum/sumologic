## DarkTrace - Auditing Aggregating Logs Per Day for History of a Source Category

```
_sourcehost="darktrace" // or _sourcecategory="X"
| timeslice 1d
| count by _timeslice
| sort by _timeslice desc

// For any Source input where the log message does not include the date or time
// Aggregate the dates of logs received
// The "| sort by _timeslice desc" shows the results in order from the eldest to the newest
```

## DarkTrace - Threat Model Detections

```
(_source="darktrace" // and _collector="hosted")
| json field=_raw "breachUrl" as Breached_URL

// Replace using Literal String method == value "https://<hostname>/<#modelbreach/breachID>" with value "https://<ipaddr>/" to allow hyperlink pivot instantly into the incident..
// | replace(Breached_URL, "https://<hostname>/","https://<ipaddr>/") as Breach_URL

// Instead of using a replace, use concatenate operator instead - This is because the log is sent from hostname but there is no DNS entry to resolve so the investigation link is not clickable
| where Breached_URL matches "https://<hostname>*" // We know the Breached URL raw log message will always include the following in the log where "*" is a wildcard for anything 
| parse field = Breached_URL "https://<hostname>-*/#*" as F1,F2 // Creating F1 as the middle part of the initial log raw message and F2 as the hashtag + sub-URL for investigation
| concat("https://<ipaddr>/#",F2) as Breach_URL // Then concetanate our string which replaces the raw log message with the IP and TAC's on the Sub-URL

// Example TOURL operator which turns the current value from the log message into a hyperlink
//| tourl(Breach_URL,"Click Here to Investigate") as Breach_URL_Click

// Example Advanced TOURL operator which turns the current value from the log message into a hyperlink but inserts a dynamic value after the common string.. Common string being ""
| tourl(Breach_URL, F2,"CLICK HERE - Dark Trace Model Breach Assignment: ","") as Breach_URL_Click
// For this to work, the resulting field "Breach_URL_Click" must be aggregated

| fields - F1,F2,Breached_URL // Remove unwanted fields used as temporary above to reduce noise

| json field=_raw "model.name" as Intelligence_Model
| json field=_raw "model.actions.breach" as Breach_Detection_Verdict
| json field=_raw "model.priority" as Breach_Priority
| json field=_raw "model.description" as Detect_Description
| json field=_raw "model.behaviour" as Behavior_Verdict
| json field=_raw "score" as Threat_Score
| where Threat_Score >= 0.9
| json field=_raw "device.ip" as Device_IP

| count by Device_IP, Threat_Score, Breach_Priority, Behavior_Verdict, Detect_Description, Breach_URL_Click
| fields -_count
| sort by Threat_Score
```
