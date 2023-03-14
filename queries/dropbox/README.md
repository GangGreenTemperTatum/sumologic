## Dropbox - Identify files accessed, editing and movement activity by user and geo-location

```
_source="dropbox"
| json field=_raw "context.email" as user
| json field=_raw "origin.geo_location.country" as user_country nodrop
| json field=_raw "origin.geo_location.region" as user_region nodrop
| json field=_raw "origin.geo_location.city" as user_city nodrop
| json field=_raw "origin.geo_location.ip_address" as user_ip
| concat(user_country, ", ", user_region, " ,", user_city) as user_location 
| json field=_raw "$['event_type']['.tag']" as event | where event contains "file"
| json field=_raw "assets[0].display_name" as filename
| json field=_raw "assets[0].path.namespace_relative.is_shared_namespace" as isfileshared
| json field=_raw "$['actor']['user']['.tag']" as isactormemberofteam
| json field=_raw "assets[0].file_id" as fileid
| json field=_raw "$['origin']['access_method']['end_user']['.tag']" as origin_access_method
| count by event, user, user_location, user_ip, filename, fileid, isfileshared, isactormemberofteam, origin_access_method
```
