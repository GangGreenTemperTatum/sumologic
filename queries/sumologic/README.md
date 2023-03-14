## Monitoring Log Ingestion Failures

```
_index=sumologic_volume sizeInBytes _sourceCategory="collector_volume" 
| parse regex "\"(?<collector>[^\"]+)\"\:\{\"sizeInBytes\"\:(?<bytes>\d+),\"count\"\:(?<count>\d+)\}" multi 
| first(_messagetime) as MostRecent, sum(bytes) as TotalVolumeBytes by collector 
| formatDate(fromMillis(MostRecent),"yyyy/MM/dd HH:mm:ss") as MostRecentTime 
| toMillis(now()) as currentTime 
| formatDate(fromMillis(currentTime),"yyyy/MM/dd HH:mm:ss") as SearchTime 
| (currentTime-MostRecent) / 1000 / 60 as mins_since_last_logs 
| where mins_since_last_logs >= 60 
| fields -mostrecent, currenttime 
| format ("%s Has not collected data in the past 60 minutes", collector) as message
```

## AUDIT - Check Scheduled Search Triggers Fired

```
_index=sumologic_audit _Sourcecategory=scheduled_search 
| where toLowerCase(_raw) contains "trigger"
```

## AUDIT Check Enterprise Search Audit index for Scheduled Search Queries History

```
_view=sumologic_search_usage_per_query query_type = "Scheduled Search"
| where user_name = "<user-sumo-account>" // "probably you" I.E Query Owner
| where toLowerCase(query) contains "crowdstrike" // "Something Relevant" I.E whatever content is within the query which can signify that specific query
```

## AUDITING - Count sourceCategory Logs Per Day

```
_index=sumologic_volume _sourceCategory=sourceCategory_volume
| parse regex "\"(?<sourceName>[^\"]+)\"\:\{\"sizeInBytes\"\:(?<bytes>\d+),\"count\"\:(?<count>\d+)\}" multi 
| where sourceName matches "<company>/darktrace" OR sourceName matches "<company>/suricata-ids"
| timeslice 1d
| count by _timeslice, sourceName
| sort by _timeslice
```

## Auditing Aggregating Logs Per Day for History of a Source Category

```
_sourceCategory=""
| timeslice 1d
| count by _timeslice, _sourceCategory
| sort by _timeslice desc

// For any Source input where the log message does not include the date or time
// Aggregate the dates of logs received
// The "| sort by _timeslice desc" shows the results in order from the eldest to the newest
```

## Auditing Last Log History of a Source Category

```
_sourceCategory=X 
| sort by _messagetime asc
| limit 10


// Useful for audits and history tracking and such
// Example of searching from a Source or SourceCategory and looking for the earliest log of the defined period
// Also, limit to 10 logs if you want an efficient and non-bulky search to literally show the last time a log was ingested

// Sumo default _messagetime, which is the time Sumo received/indexed the log WITH the 'timestamp' which is the time of the log that was sent from the Collector
// | timestamp as _messagetime
```

## Auditing Data Volume Index for Ingestion Log Count and Size per-Source

```
_view=volume_index_optimized_sourcecategory_by_tier
| timeslice 1d
| sum(msgcount) as msgcount, sum(gbytes) as gbytes by datatier, sourceCategory, _timeslice
```

## Auditing Log History Total Amount of a Source Category over Date

```
_index=sumologic_volume _sourceCategory=sourcehost_volume
| parse regex "\"(?<sourceName>[^\"]+)\"\:\{\"sizeInBytes\"\:(?<bytes>\d+),\"count\"\:(?<count>\d+)\}" multi 
| where sourceName contains "X"
| count by sourceName
```

## Auditing Source Categories by Volume (GB)

```
_view=volume_index_optimized_sourcecategory sourcecategory="<company>/tenable"
//// use the below logic to collapse high cardinality sourcecategories
//| parse field=sourcecategory "*/*/*" as f1, f2, f3 nodrop
//| parse field=sourcecategory "*/*/*/*" as f1, f2, f3, f4 nodrop
//| parse field=sourcecategory "*.*.*" as f1, f2, f3 nodrop
//| parse field=sourcecategory "*.*.*.*" as f1, f2, f3, f4 nodrop
//| concat(f1, "/", f2) as sourcecategory1
//| concat(f1, "/", f2, "/", f3) as sourcecategory2
//| if(toLowerCase(sourcecategory) matches /k8s|prod\/app/, toLowerCase(sourcecategory2), toLowerCase(sourcecategory)) as sourcecategory
////

| timeslice 2h
| sum(gbytes) as ingest by _timeslice,  sourcecategory
| transpose row _timeslice column sourcecategory
```

## Log Ingestion Volume - Monitor a specific log ingestion volume

```
_source="<company>/aiq-linode-auditd"| timeslice 1h as _timeslice | _size/1024/1024/1024 as gbytes 
| sum(gbytes) as gbytes by _timeslice | sort by _timeslice
```

## Log Ingestion Volume - Monitor and Compare specific log ingestion volumes

```
(_sourceCategory="<company>/aiq-linode-auditd" OR _sourceCategory="<company>/aiq-linode-clamav")
//| where _sourcecategory contains "auditd"
| timeslice 1h as _timeslice | _size/1024/1024/1024 as gbytes 
| sum(gbytes) as gbytes by _timeslice,_sourcecategory
| count by _sourcecategory,_timeslice | sort by _timeslice    
```
