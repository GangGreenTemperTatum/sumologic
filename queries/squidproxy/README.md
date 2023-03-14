## SquidProxy AV Lookup URL's using lookup table of IoC's

```
(_sourceName=/var/log/squid/access.log)
| parse "GET * -" as url 
| count by url 
| lookup risk,details from <lookup-table-url> on url=url // "url" being column value of the lookup table
| where risk > 1
//| count as _sourcehost by url,risk
```
