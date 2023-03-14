* My [ClamAV](https://clamav.net) logs are shipped to a Sumo Logic Hosted Endpoint Collector using [FluentD](https://docs.fluentd.org/)

## ClamAV Logs Aggregated by Date Received

```
_sourceName=clamdscan
| timeslice 1d
| count by _timeslice
```

## ClamAV Count Logs per Host 

```
(_sourceName=clamdscan)
| timeslice 1d
| count by _sourceHost,_count,_messagetime
```

## ClamAV Detection Found Infected Files

```
_sourceName=clamdscan "FOUND"
| parse "*: * FOUND" as dir,file | count by dir,file
```

## ClamAV Scan Found Infected Files

```
(_sourceName=clamdscan)
| parse "Infected files: *" as InfectedFiles
| where InfectedFiles > 0
| timeslice 1d
| count by _sourceHost,_timeslice,InfectedFiles
| transpose row _timeslice column _sourceHost,InfectedFiles
```

