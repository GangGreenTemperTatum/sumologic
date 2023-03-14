## Identify users reading and writing files to removeable media (USB/Cloud storage)

```
_sourceCategory = code42 
| json "osHostName" AS Endpoint |json "source" AS SourceType | json "deviceUserName" AS User nodrop
| json "exposure[0]" as ExposureType | json "privateIpAddresses[0]" as IPAddress nodrop
| json auto keys "eventType","fileOwner","fileType","fileName","publicIpAddress", "sha256Checksum", "filePath", "fileSize","fileCategory","md5Checksum", "actor", "processName", "processOwner" , "removableMediaSerialNumber", "removableMediaName", "removableMediaVendor", "syncDestination", "url", "userUid"
| urlencode (User) as URLName
| tourl(concat("https://console.us.code42.com/app/#/forensic-search/search/?t0=deviceUserName&q0=IS&v0=", URLName, "&t1=exposureType&q1=IS_EITHER&v1%5B0%5D=RemovableMedia&v1%5B1%5D=ApplicationRead&v1%5B2%5D=CloudStorage&v1%5B3%5D=OutsideTrustedDomains&v1%5B4%5D=SharedToDomain&v1%5B5%5D=SharedViaLink&v1%5B6%5D=IsPublic&t2=eventTimestamp&q2=WITHIN_THE_LAST&v2=P30D"), User) as User
| where ExposureType="RemovableMedia"
| count as ExposureCount by ExposureType, User 
| sort by ExposureType
| top 10 User, ExposureType by ExposureCount
```

## Identify users accessing auditing and compliance documentation (SOC2/ISO.) including Confidential data

```
((_sourcecategory="code42" "ISO" OR "SOC"))
| parse "\"deviceUserName\": \"*\"" as Username
| parse "\"osHostName\": \"*\"," as DeviceName
| parse "\"fileName\": \"*\"" as FileName
| where FileName contains "ISO" // | where FileName contains "SOC" 
| parse "\"removableMediaName\": *," as RemovableMedia
| timeslice 1d
| count by _timeslice, Username, DeviceName, FileName, RemovableMedia
// | count as Confidential_File_Access by _count, Username 
| sort by _count
| top 10 Username
```

## Identify users accessing torrents

```
_sourceCategory="code42"
| json "fileName" as file | where file contains "torrent" | json "deviceUserName" as user | json "osHostName" as host | json "publicIpAddress" as ip nodrop 
| count by file,user,host,ip
| sort by user
```
