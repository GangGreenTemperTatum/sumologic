* My [Sonarqube](https://www.sonarsource.com/products/sonarqube/) logs are shipped to a Sumo Logic Hosted Endpoint Collector using [FluentD](https://docs.fluentd.org/)

## SonarCloud Bugs all Status

```
_source="sonarqube"
| json field=_raw "type" as Code_Issue_Type
// Issue Type is defined as either Bug, Vulnerability or Code Smell with an associated Severity of 1-5
// https://docs.sonarqube.org/latest/user-guide/issues/

| where Code_Issue_Type contains "Bug"

| json field=_raw "hash" as Scan_Hash
| json field=_raw "severity" as Code_Issue_Severity

// Take the SonarQube Severity string and classify each as integer values for efficient use of sorting by

| if(Code_Issue_Severity="BLOCKER",1, 
 if(Code_Issue_Severity="CRITICAL",2,  
 if(Code_Issue_Severity="MAJOR",3, 
 if(Code_Issue_Severity="MINOR",4, 
 if(Code_Issue_Severity="INFO",5,"None"))))) as Code_Issue_Severity_Integer

| json field=_raw "author" as Code_Author
| json field=_raw "project" as Code_Project
| json field=_raw "component" as Code_Component
| json field=_raw "rule" as SonarQube_Rule
| json field=_raw "status" as Status
| json field=_raw "organization" as Organization

| count by Code_Issue_Type,Code_Issue_Severity,Code_Issue_Severity_Integer,Code_Author,Code_Project,Code_Component,SonarQube_Rule,Status

// | num(Code_Issue_Severity_Integer) | sort by +Code_Issue_Severity_Integer // "+" sorts by ascending ASC
| sort by +Code_Issue_Severity_Integer
```

## SonarCloud Bug Code Smells

```
_source="sonarqube"
| json field=_raw "type" as Code_Issue_Type
// Issue Type is defined as either Bug, Vulnerability or Code Smell with an associated Severity of 1-5
// https://docs.sonarqube.org/latest/user-guide/issues/

| where Code_Issue_Type contains "CODE_SMELL"

| json field=_raw "hash" as Scan_Hash
| json field=_raw "severity" as Code_Issue_Severity

// Take the SonarQube Severity string and classify each as integer values for efficient use of sorting by

| if(Code_Issue_Severity="BLOCKER",1, 
 if(Code_Issue_Severity="CRITICAL",2,  
 if(Code_Issue_Severity="MAJOR",3, 
 if(Code_Issue_Severity="MINOR",4, 
 if(Code_Issue_Severity="INFO",5,"None"))))) as Code_Issue_Severity_Integer

| json field=_raw "author" as Code_Author
| json field=_raw "project" as Code_Project
| json field=_raw "component" as Code_Component
| json field=_raw "rule" as SonarQube_Rule
| json field=_raw "status" as Status
| json field=_raw "organization" as Organization

| count by Code_Issue_Type,Code_Issue_Severity,Code_Issue_Severity_Integer,Code_Author,Code_Project,Code_Component,SonarQube_Rule,Status

// | num(Code_Issue_Severity_Integer) | sort by +Code_Issue_Severity_Integer // "+" sorts by ascending ASC
| sort by +Code_Issue_Severity_Integer
```

## SonarCloud Bugs Code Vulnerabilities

```
_source="sonarqube"
| json field=_raw "type" as Code_Issue_Type
// Issue Type is defined as either Bug, Vulnerability or Code Smell with an associated Severity of 1-5
// https://docs.sonarqube.org/latest/user-guide/issues/

// | where Code_Issue_Type contains "Vulnerability"

| json field=_raw "hash" as Scan_Hash
| json field=_raw "severity" as Code_Issue_Severity

// Take the SonarQube Severity string and classify each as integer values for efficient use of sorting by

| if(Code_Issue_Severity="BLOCKER",1, 
 if(Code_Issue_Severity="CRITICAL",2,  
 if(Code_Issue_Severity="MAJOR",3, 
 if(Code_Issue_Severity="MINOR",4, 
 if(Code_Issue_Severity="INFO",5,"None"))))) as Code_Issue_Severity_Integer

| json field=_raw "author" as Code_Author
| json field=_raw "project" as Code_Project
| json field=_raw "component" as Code_Component
| json field=_raw "rule" as SonarQube_Rule
| json field=_raw "status" as Status
| json field=_raw "organization" as Organization

| count by Code_Issue_Type,Code_Issue_Severity,Code_Issue_Severity_Integer,Code_Author,Code_Project,Code_Component,SonarQube_Rule,Status

// | num(Code_Issue_Severity_Integer) | sort by +Code_Issue_Severity_Integer // "+" sorts by ascending ASC
| sort by +Code_Issue_Severity_Integer
```

## SonarCloud Bugs Code Vulnerabilities All Status

```
_source="sonarqube"
| json field=_raw "type" as Code_Issue_Type
// Issue Type is defined as either Bug, Vulnerability or Code Smell with an associated Severity of 1-5
// https://docs.sonarqube.org/latest/user-guide/issues/

| where Code_Issue_Type contains "Vulnerability"

| json field=_raw "hash" as Scan_Hash
| json field=_raw "severity" as Code_Issue_Severity

// Take the SonarQube Severity string and classify each as integer values for efficient use of sorting by

| if(Code_Issue_Severity="BLOCKER",1, 
 if(Code_Issue_Severity="CRITICAL",2,  
 if(Code_Issue_Severity="MAJOR",3, 
 if(Code_Issue_Severity="MINOR",4, 
 if(Code_Issue_Severity="INFO",5,"None"))))) as Code_Issue_Severity_Integer

| json field=_raw "author" as Code_Author
| json field=_raw "project" as Code_Project
| json field=_raw "component" as Code_Component
| json field=_raw "rule" as SonarQube_Rule
| json field=_raw "status" as Status
| json field=_raw "organization" as Organization

| count by Code_Issue_Type,Code_Issue_Severity,Code_Issue_Severity_Integer,Code_Author,Code_Project,Code_Component,SonarQube_Rule,Status

// | num(Code_Issue_Severity_Integer) | sort by +Code_Issue_Severity_Integer // "+" sorts by ascending ASC
| sort by +Code_Issue_Severity_Integer
```
