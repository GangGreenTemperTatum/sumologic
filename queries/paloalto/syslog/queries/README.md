* My [Palo Alto Firewall](https://www.paloaltonetworks.com/) logs are shipped to a Sumo Logic Hosted Endpoint Collector using [FluentD](https://docs.fluentd.org/)

## Palo Alto GlobalConnect Corporate VPN Authentication Simultaneous Logins

```
_sourceCategory="security/platform/infra/globalconnectvpn"
// Do not need to parse out date/day/month and time as ingesting from FluentD is displaying correct timestamp in _messageTime (Sumo default)
// Drop Regex Parse as we use native CSV parse function below
//| parse regex "\,(?<email>\w+\.?\w+@\w+\.\w+)\," nodrop
//| parse regex "(?<mac>[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+)" nodrop

// See what Sumo interprets the CSV fields as using the native built-in CSV parse mechanism to define fields
//| csv CSV_Message extract 13 as User, 9 as VPN_Event, 10 as VPN_Message, 15 as Hostname, 16 as Public_IP, 20 as MacAddress, 21 as Serialnum, 22 as result22, 23 as result23, 24 as result24

// Have to include the parse statement below as "| csv _raw" does not work due to User-Agent containing ""
| parse "* * * *.<company>* *" as Month,Day_Num,Time,VPN_Gateway,F2,CSV_Message // F3 meaning anything WILDCARD after the space following the domain
// The value after the 'extract' keyword evaluates the "X" numbered position of the CSV value from the log
| csv CSV_Message extract 13 as User, 9 as VPN_Event, 10 as VPN_Message, 15 as Hostname, 16 as Public_IP, 20 as MacAddress, 21 as Serialnum, 24 as remainder
| lookup latitude, longitude, country_code from geo://location on ip=Public_IP
| fields -Month,Day_Num,Time,F2
| if(remainder contains "success", "success", "") as Result
| if(remainder contains "failure", "failure", result) as Result

// Note, the VPN client stores authentication cookies and after initial connection which does not require multi re-auths (difference between gateway-auth and portal-auth VPN Events)
| where !(VPN_Event contains "config") AND !(VPN_Event contains "latency") 
//| count VPN_Event, VPN_Message, Result
// Looks like Result only contains success or failure
// To differentiate VPN logins, cannot use MAC/User-Agent or PublicIPv4 as these can be spoofed or legit.. Gives us only the timestamp to really differentiate logins

| timeslice 1m // Differentiate login attempts of 1 minute which would be almost impossible to login from two locations/machines within the same second and should not generate any FP's
| where toLowerCase(Result) = "success"
| where toLowerCase(VPN_Message) = "login" AND (VPN_Event="portal-auth")
// Count unique combinations of timeslice, user and public IP
| count by _timeslice, User, Public_IP, MacAddress, Serialnum, VPN_Message, VPN_Event, Result, country_code
| where _count >1 // This person authenticated more than once, within a minute which may provide FP's but is more likely to generate data than 1second as that is almost impossible 
// Forensic search of simply identifying users matching this query | count by User

// Aggregate by coordinates if you wish to view on a Geo-Map
// | count by _timeslice, User, Public_IP, MacAddress, Serialnum, VPN_Message, VPN_Event, Result, latitude, longitude, country_code
```

## Palo Alto GlobalConnect Corporate VPN Authentication Simultaneous Logins - Geo

```
_sourceCategory="security/platform/infra/globalconnectvpn"
// Do not need to parse out date/day/month and time as ingesting from FluentD is displaying correct timestamp in _messageTime (Sumo default)
// Drop Regex Parse as we use native CSV parse function below
//| parse regex "\,(?<email>\w+\.?\w+@\w+\.\w+)\," nodrop
//| parse regex "(?<mac>[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+\:[a-z0-9]+)" nodrop

// See what Sumo interprets the CSV fields as using the native built-in CSV parse mechanism to define fields
//| csv CSV_Message extract 13 as User, 9 as VPN_Event, 10 as VPN_Message, 15 as Hostname, 16 as Public_IP, 20 as MacAddress, 21 as Serialnum, 22 as result22, 23 as result23, 24 as result24

// Have to include the parse statement below as "| csv _raw" does not work due to User-Agent containing ""
| parse "* * * *.<company>* *" as Month,Day_Num,Time,VPN_Gateway,F2,CSV_Message // F3 meaning anything WILDCARD after the space following the domain
// The value after the 'extract' keyword evaluates the "X" numbered position of the CSV value from the log
| csv CSV_Message extract 13 as User, 9 as VPN_Event, 10 as VPN_Message, 15 as Hostname, 16 as Public_IP, 20 as MacAddress, 21 as Serialnum, 24 as remainder
| lookup latitude, longitude, country_code from geo://location on ip=Public_IP
| fields -Month,Day_Num,Time,F2
| if(remainder contains "success", "success", "") as Result
| if(remainder contains "failure", "failure", result) as Result

// Note, the VPN client stores authentication cookies and after initial connection which does not require multi re-auths (difference between gateway-auth and portal-auth VPN Events)
| where !(VPN_Event contains "config") AND !(VPN_Event contains "latency") 
//| count VPN_Event, VPN_Message, Result
// Looks like Result only contains success or failure
// To differentiate VPN logins, cannot use MAC/User-Agent or PublicIPv4 as these can be spoofed or legit.. Gives us only the timestamp to really differentiate logins

| timeslice 1m // Differentiate login attempts of 1 minute which would be almost impossible to login from two locations/machines within the same second and should not generate any FP's
| where toLowerCase(Result) = "success"
| where toLowerCase(VPN_Message) = "login" AND (VPN_Event="portal-auth")
// Count unique combinations of timeslice, user and public IP
//| count by _timeslice, User, Public_IP, MacAddress, Serialnum, VPN_Message, VPN_Event, Result, country_code
 // This person authenticated more than once, within a minute which may provide FP's but is more likely to generate data than 1second as that is almost impossible 
// Forensic search of simply identifying users matching this query | count by User

// Aggregate by coordinates if you wish to view on a Geo-Map
| count by _timeslice, User, Public_IP, MacAddress, Serialnum, VPN_Message, VPN_Event, Result, latitude, longitude, country_code
| where _count >1
```

## Palo Alto GlobalProtect Corp VPN Authentication Failures

```
_source="security/globalconnectvpn" OR _sourceCategory="security/platform/infra/globalconnectvpn"
// Rsyslogd receives corporate firewall logs into /var/log/remote_syslog_vpn.log
// Shipped to Sumo immediately before the log file is rotated and retention is lost

// Since the log is in CSV format && is 1-based we create F3 as a CSV and then extract from here 
| parse "* * * *.<company>* *" as Month,Day_Num,Time,VPN_Gateway,F2,CSV_Message // F3 meaning anything WILDCARD after the space following the domain
// The value after the 'extract' keyword evaluates the "X" numbered position of the CSV value from the log
| csv CSV_Message extract 13 as User, 9 as VPN_Event, 10 as VPN_Message, 15 as Hostname, 16 as Public_IP, 29 as Result
// Include a WHERE statement to filter only logs relevant to connection events
| where VPN_Message contains "login" or VPN_Message contains "connection"

// Create two IF statements to sum the values of matching to either success or failures as an integer
| if(Result != "success", 1, 0) as Failed_VPN_Attempts // Where Failure also therefore includes other messages such as host-checks etc. - NA means no value
| if(Result = "success", 1, 0) as Successful_VPN_Attempts // Where Success messages are successful connections - NA means no value
// This is used to sum the columns where value of one is a match, otherwise no match is given value of zero

// Use the SUM operator to sum the Failed vs Successful VPN attempts (adding the 1's and 0's from above)
| sum (Failed_VPN_Attempts) as Failed_VPN_Attempts, sum (Successful_VPN_Attempts) as Successful_VPN_Attempts by User, Public_IP, VPN_Gateway, Hostname

// Perform MATH ADDITION operator to add both failed and successul as a total
| Failed_VPN_Attempts + Successful_VPN_Attempts as Total_VPN_Attempts
// Perform MATH DIVISION operator to get a ratio of failed attempts from the total
| Failed_VPN_Attempts / Total_VPN_Attempts as Failed_VPN_Attempts_Ratio

| where Failed_VPN_Attempts_Ratio >= .5 and Total_VPN_Attempts >= 3
// This may result in some duplicates as we have 15 minutes x 4 within a 60 minute window, but can adjust and tweak as necessary

// Sort by the Failed_VPN_Attempts_Ratio to show highest top-down order 
 | sort by Failed_VPN_Attempts_Ratio 
 ```
