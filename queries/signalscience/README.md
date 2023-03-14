## Identify an Aggregated Overview of Remote IPv4 Clients and Response Codes

```
_sourceCategory="<signalscience>"
| json field=_raw "remoteIP"
| where remoteIP contains "<my-ipaddr-space>" OR remoteIP contains "<my-ipaddr-space>"
| json field=_raw "responseCode"
| json field=_raw "agentResponseCode"
| count remoteIP, responseCode, agentResponseCode, _messagetime
```

## Identify Brute Force Authentication Attempts and Credential Stuffing Attacks for Real Time Alerting

```
_sourceCategory="<signalscience>" 
| json auto | fields method,path,remoteIP,userAgent,responseCode,serverName 
| where contains(path,"authenticate")  
| where !isPrivateIP(remoteIP) 
| where [subquery from=(-65m) to=(-5m): _sourceCategory="<signalscience>" 
                  | json auto | fields method,path,remoteIP,userAgent,responseCode,serverName 
                  | where contains(path,"authenticate")  
                  | where !isPrivateIP(remoteIP) 
                  | count as total_requests by remoteIP,responseCode
                  | where total_requests > 15  
| compose remoteIP]
| timeslice 5m 
// Perform 15 minute timeslices and count as the remoteIP and its server response code(s) within the timeslice but as the amount of requests from that IP within that slice in time
//| count as total_requests by _timeslice,remoteIP,responseCode
| count as total_requests by _timeslice, remoteIP
| transpose row _timeslice column remoteIP
```

## Identify Brute Force Authentication Attempts and Credential Stuffing Attacks Alerting for Remote IP's Over 3.5% of Total Requests within Past 65 Minutes

```
_sourceCategory="<signalscience>" 
| json auto | fields method,path,remoteIP,userAgent,responseCode,serverName 
| where contains(path,"authenticate")  
| where !isPrivateIP(remoteIP) 
//| timeslice 15m 

| concat ("https://app.recordedfuture.com/live/sc/entity/ip:/",remoteIP) as tmp
| toUrl(tmp,"Investigate IP Address in Recorded Future") as Recorded_Future_Intel_Link
| fields -tmp

| count as total_requests_ip by remoteIP,responseCode,Recorded_Future_Intel_Link
| total total_requests_ip as total_requests_agg

| where total_requests_agg >= X <---- Include this line if the threshold is alerting too much when beneath the baseline of traffic and therefore receiving benign FP traffic that is legit (I.E high users of the application)

| total_requests_ip / total_requests_agg as total_requests_prc
| sort by total_requests_prc desc
| where total_requests_prc > .035 // Could also use Sumo Logic built-in "percentile" operator instead of hard-code percentage 0.35%
| format("%.1f %s", total_requests_prc*100,"%") as total_requests_prc
```
* This search displays inbound WAF logs  and filters for any GET requests to the authentication login path which do not include a HTTP status code of 200
* The output is aggregated to display the status code and remote IP address
* Further IR can be then performed on the correlating logs to deep-dive into the attacker

```
_sourceCategory="<signalscience>" 
| json auto | fields method,path,remoteIP,userAgent,responseCode, serverName 
| where responseCode != 200 // Remove HTTP 200 OK responses
| where contains(path,"/<PATH>/authenticate")  
| where !isPrivateIP(remoteIP) 
| timeslice 15m 
| count by _timeslice,remoteIP,responseCode 
| where _count > 15 
| transpose row _timeslice column responseCode,remoteIP
// HTTP Status code 401 Unauthorized / 403 Forbidden / 405 Not Allowed / 406 Not Acceptable / 407 Proxy authentication required
```

* As geo-represented:

```
_sourceCategory="<signalscience>" 
| json auto | fields HTTP_Method,Path,RemoteIP,UserAgent,ResponseCode, ServerName 
| where responseCode != 200 // Remove HTTP 200 OK responses
| where contains(path,"/am/json/realms/root/realms/authtree/authenticate")  
| where !isPrivateIP(RemoteIP) 
// The isPrivateIP operator checks if an IPv4 address is private and returns a boolean.
| where remoteIP != "<my-ipaddr-space>"
| lookup latitude, longitude from geo://location on ip=RemoteIP 
| timeslice 15m      
| count by _timeslice,latitude,longitude,RemoteIP,ResponseCode 
| where _count > 15 
// | transpose row _timeslice column latitude,longitude,ResponseCode,RemoteIP // Including the Transponse operator removes the ability to perform Geo-Map format presentation
// HTTP Status code 401 Unauthorized / 403 Forbidden / 405 Not Allowed / 406 Not Acceptable / 407 Proxy authentication required
```

## Identify 60 Minute Window Anomaly Detection Events Sub-Query 
* This is the alert we process based on our accepted threshold and is analyzed with the above query

```
_sourceCategory="<signalscience>" 
| json auto | fields method,path,remoteIP,userAgent,responseCode,serverName 
| where path != "/favicon.ico" 
| where !isPrivateIP(remoteIP)
| where responseCode = "400" or responseCode = "403" or responseCode = "404" or responseCode = "405" or responseCode = "406" or responseCode = "408" or responseCode = "429" or responseCode = "500" or responseCode = "505"

| toUrl(concat("https://service.<sumoregion>.sumologic.com/ui/#/search/@-24h@",remoteIP), remoteIP) as remoteIP_click
| concat ("https://app.recordedfuture.com/live/sc/entity/ip:/",remoteIP) as tmp
| toUrl(tmp,"Investigate IP Address in Recorded Future") as Recorded_Future_Intel_Link
| fields -tmp

| count as total_requests_ip by remoteIP_click,responseCode,Recorded_Future_Intel_Link
| total total_requests_ip as total_requests_agg
| total_requests_ip / total_requests_agg as total_requests_prc
| sort by total_requests_prc desc
| where total_requests_prc > 0.1
| format("%.1f %s", total_requests_prc*100,"%") as total_requests_prc
```

* 15 Minute timeslices within 65 minute window (offset by 5 minutes) within the subquery so sub-query has a smaller trend within the parent query of one day

```
_sourceCategory="<signalscience>" 
| json auto | fields method,path,remoteIP,userAgent,responseCode,serverName 
| where path != "/favicon.ico" 
| where !isPrivateIP(remoteIP)
| toUrl(concat("https://service.<sumoregion>.sumologic.com/ui/#/search/@-24h@",remoteIP), remoteIP) as remoteIP_click

| where responseCode = "400" or responseCode = "403" or responseCode = "404" or responseCode = "405" or responseCode = "406" or responseCode = "408" or responseCode = "429" or responseCode = "500" or responseCode = "505"
| where [subquery from=(-65m) to=(-5m): _sourceCategory="<signalscience>" 
                  | json auto | fields method,path,remoteIP,userAgent,responseCode, serverName 
                  | where path != "/favicon.ico" 
                  | where !isPrivateIP(remoteIP) 
                  | where responseCode = "400" or responseCode = "403" or responseCode = "404" or responseCode = "405" or responseCode = "406" or responseCode = "408" or responseCode = "429" or responseCode = "500" or responseCode = "505" 
                  | count as total_requests by remoteIP,responseCode 
                  | where total_requests > 50
| compose remoteIP]   
| timeslice 15m 
| count as total_requests by _timeslice,remoteIP_click,responseCode
| transpose row _timeslice column remoteIP_click,responseCode
```

## Putting this all together with enriching this data with [Recorded Future](https://www.recordedfuture.com/threat-intelligence) Threat Intelligence Module Data In Another Table

```
// Parent
_sourceCategory="<signalscience>" 

// parsing and formatting
| json auto 
| fields method,path,remoteIP,userAgent,responseCode,serverName 
| where path != "/favicon.ico" 
| where !isPrivateIP(remoteIP)
| where responseCode = "400" or responseCode = "403" or responseCode = "404" or responseCode = "405" or responseCode = "406" or responseCode = "408" or responseCode = "429" or responseCode = "500" or responseCode = "505"

// format link to recorded future
| concat ("https://app.recordedfuture.com/live/sc/entity/ip:/",remoteIP) as tmp
| toUrl(tmp,"Investigate IP Address in Recorded Future") as Recorded_Future_Intel_Link
| fields -tmp

// aggregate and format to reduce noise
| toUrl(concat("https://service.<sumoregion>.sumologic.com/ui/#/search/@-24h@",remoteIP), remoteIP) as remoteIP_click
| count as total_requests_ip by remoteIP_click,responseCode,Recorded_Future_Intel_Link
| total total_requests_ip as total_requests_agg 
| where total_requests_agg > 1000
| total_requests_ip / total_requests_agg as total_requests_prc
| sort by total_requests_prc desc

// filter to >0,1. could also use parameter to be dynamic and fancy
| where total_requests_prc > 0.0.5 // Could also use "percentile" operator instead of hard-code percentage
| format("%.1f %s", total_requests_prc*100,"%") as total_requests_prc
| "include" as temp

//Sub-Query
| where [subquery:_source="<recordedfuture>" 
          | json field=_raw "ip_address" as Remote_IP
          | json field=_raw "data.risk.score" as Risk_Score
          | count by Risk_Score,Remote_IP
          | "include" as temp
          | save RFriskscore_for_IPAddresses
          | compose temp
]

| lookup Risk_Score from RFriskscore_for_IPAddresses on Remote_IP=remoteIP_click
| fields -temp
| where risk_score > {{minimum_risk_score}}
| sort by risk_score DESC
```

```
_source="<signalscience>_integration" "<my-ipaddr-space>"

| json field=_raw "payload.exampleRequest.remoteIP" as RemoteIP nodrop
| json field=_raw "payload.remoteCountryCode" as RemoteCountry nodrop
| json field=_raw "payload.userAgents" as RemoteUserAgent nodrop
| json field=_raw "payload.exampleRequest.path" as Path nodrop

| json field=_raw "payload.action" as Action nodrop
| json field=_raw "payload.type" as Type nodrop
| json field=_raw "payload.reasons" as EventAlert nodrop
| json field=_raw "payload.requestCount" as EventCount nodrop
// Key range to parse all key/value pairs within this array path
| json field=_raw "payload.exampleRequest.tags[*].type" as SSTags

| json field=_raw "payload.exampleRequest.responseCode" as ResponseCode nodrop

// format link to recorded future
| concat ("https://app.recordedfuture.com/live/sc/entity/ip:/",RemoteIP) as tmp
| toUrl(tmp,"Investigate IP Address in Recorded Future") as Recorded_Future_Intel_Link 
| fields -tmp

// aggregate and format to reduce noise
| toUrl(concat("https://service.<sumoregion>.sumologic.com/ui/#/search/@-24h@",RemoteIP), RemoteIP) as RemoteIPSumo

| count by RemoteIPSumo, Recorded_Future_Intel_Link, RemoteCountry, RemoteUserAgent, Path, Type, EventAlert

//| count as total_requests_ip by remoteIP_click,responseCode,Recorded_Future_Intel_Link
//| total total_requests_ip as total_requests_agg 
//| where total_requests_agg > 1000
//| total_requests_ip / total_requests_agg as total_requests_prc
//| sort by total_requests_prc desc
//
//// filter to >0,1. could also use parameter to be dynamic and fancy
//| where total_requests_prc > 0.1 // Could also use "percentile" operator instead of hard-code percentage
//| format("%.1f %s", total_requests_prc*100,"%") as total_requests_prc
//| "include" as temp
//
//Sub-Query
//| where [subquery:_source="<recordedfuture>"   
//          | json field=_raw "ip_address" as Remote_IP
//          | json field=_raw "data.risk.score" as Risk_Score  
//          | count by Risk_Score,Remote_IP
//          | "include" as temp 
//          | save RFriskscore_for_IPAddresses
//          | compose temp
//] 

//| lookup Risk_Score from RFriskscore_for_IPAddresses on Remote_IP=RemoteIP
//| fields -temp
//| where risk_score >= 1
//| sort by risk_score DESC
```

## Identify Signal Science Agent-related Alerts:

```
_sourceCategory="<signalscience>_integration" "Agent \"*\ came online" OR "Agent \"*\ offline"
```

## Identify Anomaly Errors from Status Codes:

```
_sourceCategory="<signalscience>"
| json auto | fields method,path,remoteIP,userAgent,responseCode, serverName 
| where path != "/favicon.ico" 
| where !isPrivateIP(remoteIP)
| where remoteIP != "<Insert-Whitelisted-IPs>"
| where responseCode = "400" or responseCode = "403" or responseCode = "404" or responseCode = "405" or responseCode = "406" or responseCode = "408" or responseCode = "429" or responseCode = "500" or responseCode = "505"
| timeslice 15m | count by _timeslice,responseCode,remoteIP | where _count > 50 | transpose row _timeslice column responseCode,remoteIP
//| count by remoteIP,responseCode | sort _count
//| count responseCode 
// bad request (400), forbidden (403), not found (404), method not allowed (405), not acceptable (406), request timeout (408), to many requests (429), server error (500), http not supported (505)
```

* As geo-represented:

```
// Signal Sciences Anomaly Area based on Geo
_sourceCategory="<signalscience>"
| parse "\"serverName\": \"*\"" as Server_Name
| parse "\"responseCode\": *," as Response_Code
| parse "\"userAgent\": \"*\"" as User_Agent
| parse "\"method\": \"*\"" as HTTP_Method
| parse "\"remoteIP\": \"*\"" as Remote_IP
| parse "\"remoteCountryCode\": \"*\"" as Remote_Country_Code
| parse "\"path\": \"*\"" as Path
// favicon.ico icons are displayed in the address bar of every browser and as such we want to ignore these
| where path != "/favicon.ico" 
// The isPrivateIP operator checks if an IPv4 address is private and returns a boolean.
| where !isPrivateIP(Remote_IP)
| where remoteIP != "xxx.xxx.xxx.xxx"
// Filter for specific HTTP response codes (considered bad requests)
// bad request (400), forbidden (403), not found (404), method not allowed (405), not acceptable (406), request timeout (408), to many requests (429), server error (500), http not supported (505)
| where responseCode = "400" or responseCode = "403" or responseCode = "404" or responseCode = "405" or responseCode = "406" or responseCode = "408" or responseCode = "429" or responseCode = "500" or responseCode = "505"
| lookup latitude, longitude from geo://location on ip=Remote_IP 

// Perform individual timeslice of 15 minutes where we match the above conditions within 15 minute intervals which would be relevant in a table format
// To map the IP addresses properly you must count by the latitude and longitude fields. You must have the _count field in your results.
// We also provide a greater-than WHERE statement which indicates that the count of ALL the above conditions must be more than 50 to be considered a threat
| timeslice 15m | count by latitude, longitude, Remote_Country_Code _timeslice, Response_Code, Remote_IP | where _count > 50
// Sort tabled-results by the count of the matched conditions above and Response Code so Responde Codes are scattered
| sort by _count, Response_Code
```

## Identify WAF Detection of "log4j - JNDI" vulnerability exploit attempts

```
_sourcecategory="<signalscience>" or _sourceCategory="<signalscience>_testfiary"
| json field=_raw "serverHostname" as ServerHostname
| json field=_raw "remoteCountryCode" as RemoteCountryCode
| json field=_raw "remoteHostname" as RemoteHostname

| json field=_raw "remoteIP" as RemoteIP
| where !isPrivateIP(RemoteIP) 
| lookup ip from path://"/Library/Users/users/WhiteList-IPs on RemoteIP=ip

| if (isNull(ip), "no_ip", ip) as ipnon<myips>
| where ipnon<myips>="no_ip"
//| fields - name, name1, _raw

// | where !(RemoteIP contains "xxx.xxx.xxx") | where !(RemoteIP contains "xxx.xxx.xxx")

| toUrl(concat("https://service.<sumoregion>.sumologic.com/ui/#/search/@-24h@",RemoteIP), RemoteIP) as RemoteIP_Click 

| concat ("https://app.recordedfuture.com/live/sc/entity/ip:/",RemoteIP) as tmp
| toUrl(tmp,"Investigate IP Address in Recorded Future") as Recorded_Future_Intel_Link
| fields -tmp

| lookup latitude, longitude, country_code, country_name, region, city, postal_code, state from geo://location on ip=RemoteIP
| lookup type, actor, raw, threatlevel as malicious_confidence from sumo://threat/cs on threat=RemoteIP
| if (isEmpty(actor), "Unassigned", actor) as Actor

// | fields -latitude, longitude

| json field=_raw "userAgent" as UserAgent
| where UserAgent contains "jndi"
| base64Decode(userAgent, "UTF-16LE") as V

| json field=_raw "serverName" as ServerName
| json field=_raw "method" as HTTP_Method
| json field=_raw "path" as Path
| json field=_raw "responseCode" as SS_HTTP_RC
| where SS_HTTP_RC != "406" // | where SS_HTTP_RC != "403"

| count by ServerName, Path, latitude, longitude, country_code, country_name, region, city, postal_code, state, RemoteIP_Click, UserAgent, SS_HTTP_RC,Recorded_Future_Intel_Link
| sort by _count
```
