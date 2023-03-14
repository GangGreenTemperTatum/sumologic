## IAM Access Logs - Identity and Access Management

```
_source="gcp_iam_<region>"
| json "message.data" 
| base64decode(%"message.data") as raw_data
```

## IAM Key Usage Audit with Geo Representation

```
_source="gcp_iam_<region>"
| json "message.data" 
| base64decode(%"message.data") as raw_data
| json field=raw_data "resource.type"
| json field=raw_data "protoPayload.authenticationInfo.principalEmail" as email
| json field=raw_data "protoPayload.requestMetadata.callerIp" as ip
| where !isPrivateIp(ip)
| where !(ip matches "xxx.xxx.xxx.xxx") and !(ip matches "xxx.xxx.xxx.xxx")// Exclude our own custom CIDR's to prevent noise from our own traffic of micro segmented architecture
| where !(ip matches "xxx.xxx.xxx.xxx") // GCP netblock 
| lookup latitude, longitude, country_code, country_name, region, city, postal_code from geo://location on ip = ip 
| count by email,ip, country_code, country_name, city
```
