# Setup Instructions

1. Download & install the [Deep Security SDK](https://automation.deepsecurity.trendmicro.com/article/12_5/python?platform=dsaas).
2. Create Deep Security [API keys](https://automation.deepsecurity.trendmicro.com/article/11_1/create-and-manage-api-keys?platform=dsaas#create-an-api-key-in-deep-security-manager).
3. Set the API key as a `DS_KEY` environment variable.

# Usage Instructions
## Help Menu

```
$ python3 reporter.py -h
usage: reporter.py [-h] [--report-filename REPORT_FILENAME]
                   [--summary-filename SUMMARY_FILENAME]
                   [--app-names [APP_NAMES [APP_NAMES ...]]] --dsm-address
                   DSM_ADDRESS

Deep Security IPS Report

optional arguments:
  -h, --help                               show this help message and exit
  --report-filename REPORT_FILENAME        IPS report filename (default: ips_report.csv
  --summary-filename SUMMARY_FILENAME      IPS summary filename (default: ips_summary.csv
  --app-names [APP_NAMES [APP_NAMES ...]]  App names to search for in the IPS report

required arguments:
  --dsm-address DSM_ADDRESS                e.g https://app.deepsecurity.trendmicro.com/api
```

## Example Usage

```
python3 reporter.py --dsm-address https://app.deepsecurity.trendmicro.com/api --app-names 'Apache Struts' 'NGINX' 'Internet Explorer'
```

Specifying `--app-names` results in an "App Name" column being added to the report CSV file. This enables users to easily group and identify vulnerable applications.

Note that the search is case insensitive. Therefore, in the above example, 'nginx', 'Nginx' and 'NGINX' would all be found.  

# Example Outputs
## Report

```
Hostname,Display Name,Host Description,Platform,Last IP Used,Agent Version,Policy ID,Last Agent Comms.,IPS Agent State,IPS Status,Rule Name,Rule ID,Rule Description,App Category,App Description,App Port(s),Direction,Protocol,CVE(s),CVSS Score,Severity,Rule Type,App Name
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Struts 'ParameterInterceptor' Class OGNL Expression Parsing Remote Command Execution,2572,Apache Struts is prone to a security-bypass vulnerability because it fails to adequately handle user-supplied input. Attackers can exploit this issue to manipulate server-side context objects with the privileges of the user running the application. Successful exploits can compromise the application and possibly the underlying computer.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,CVE-2011-3923,10.00,critical,exploit,Apache Struts
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Struts2 ParametersInterceptor Remote Command Execution,2573,A command execution vulnerability exists in the web application framework Apache Struts2. The vulnerability is due to insufficient input validation when parsing incoming HTTP requests. A remote attacker can leverage this vulnerability by sending a crafted HTTP request to a target system and execute arbitrary code remotely.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,CVE-2010-1870,5.00,medium,exploit,Apache Struts
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Struts OGNL Expression Remote Code Execution Vulnerabilities,2691,Apache Struts allows remote attackers to execute arbitrary commands via a request with specially crafted OGNL (Object-Graph Navigation Language) expressions.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,"CVE-2013-2135, CVE-2013-2134",9.30,critical,exploit,Apache Struts
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules","nginx ""ngx_http_parse_chunked()"" Buffer Overflow Vulnerability",2955,nginx is prone to a stack based buffer overflow vulnerability. Successfully exploiting this issue allows attackers to execute arbitrary code in the context of the vulnerable application. Failed exploit attempts will result in a denial of service condition.,Web Server Miscellaneous,,"80, 1099, 1408, 1581, 3612, 4848, 5984, 7100, 7101, 7510, 8043, 8080, 8081, 8083, 8088, 8090, 8093, 8094, 8161, 8300, 8443, 8500, 8800, 9000, 9060, 9080, 9090, 9832, 10001, 12345, 15050, 19300, 32000, 41080, 41443, 1220, 7080, 8700, 5986, 21009",incoming,tcp,CVE-2013-2028,7.50,high,exploit,nginx
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Tomcat Chunked Transfer Encoding Data Saturation Remote Denial Of Service Vulnerability,2957,Apache Tomcat is prone to a denial of service vulnerability. Attackers may leverage this issue to cause denial of service conditions.,Web Application Tomcat,"This application type filters traffic on common Tomcat server ports, including that of Deep Security Manager.","80, 8000, 8080, 8081",incoming,tcp,CVE-2012-3544,5.00,medium,exploit,N/A
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Nginx STARTTLS Command Injection Vulnerability,3221,"Nginx could allow a remote attacker to execute arbitrary commands on the system, caused by an error in the ngx_mail_smtp_starttls() function. An attacker could exploit this vulnerability by using the STARTTLS command to inject commands into SSL sessions and gain access to plaintext information sent by the target client.",Mail Server Common,,"25, 110, 143",incoming,tcp,CVE-2014-3556,4.30,medium,vulnerability,nginx
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Identified Suspicious User Agent In Outgoing HTTP Request,3812,"This is a heuristic based rule which identifies the suspicious user-agent header in outgoing HTTP request used for connecting to command and control server.
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",HTTP Web Client Decoding,4282,This is a smart filter that decodes the Web Client traffic and is used by other web client filters.,Web Client Common,,5,outgoing,tcp,,-1.00,critical,smart,N/A
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Apache Tomcat Commons UploadFile Denial Of Service Vulnerability,4412,Apache Tomcat is prone to denial of service vulnerability which can be exploited via crafted request.,Web Application Tomcat,"This application type filters traffic on common Tomcat server ports, including that of Deep Security Manager.","80, 8000, 8080, 8081",incoming,tcp,CVE-2014-0050,7.50,high,vulnerability,N/A
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Identified Fraudulent Digital Certificate - 1,4432,This rule heuristically prevents the exchange of Secure Socket Layer (SSL) certificate whose trust has been revoked.,Web Client SSL,,443,outgoing,tcp,,10.00,critical,smart,N/A
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",SMTP Decoding,4593,The filter decodes the SMTP Protocol and will be used by other SMTP filters. It should be enabled on all the SMTP filters. The filter will have to be active on application type listening on port 25.,Mail Server Common,,"25, 110, 143",incoming,tcp,,-1.00,critical,smart,N/A
ip-172-31-28-113.ap-southeast-2.compute.internal,,,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),192.168.22.2,12.0.0.481,9,"15/09/2019, 15:02:22 AEST",active,"On, Prevent, 50 rules",Ruby On Rails XML Processor YAML Deserialization DoS,4874,There exists a vulnerability in the parameter parsing code for Ruby on Rails which allows attackers to perform a DoS attack on a Rails application.,Web Application Ruby Based,,"80, 8080, 3000",incoming,tcp,CVE-2013-0156,7.50,high,exploit,N/A
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Identified Diginotar Certificate,2013,This filter heuristically blocks exchange of Secure Socket Layer (SSL) certificate issued by Diginotar.,Web Client SSL,,443,outgoing,tcp,,9.40,critical,smart,N/A
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Identified Fraudulent Digital Certificate,2285,"This rule heuristically prevents the exchange of Secure Socket Layer (SSL) certificate whose trust has been revoked. 
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Microsoft Internet Explorer 'Tree::Notify_InvalidateDisplay' Null Pointer Dereference Vulnerability,6425,Microsoft Internet Explorer suffers from a NULL pointer deference vulnerability. Successful exploitation could lead to a denial of service attack. This vulnerability could be used to corrupt memory and execute remote code on the client machine.,Web Client Internet Explorer/Edge,,5,outgoing,tcp,,7.20,high,exploit,Internet Explorer
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Microsoft Edge And Internet Explorer Same Origin Policy Bypass Vulnerabilities,6676,"Microsoft Edge and Internet Explorer are vulnerable to the same origin policy bypass vulnerability. Successful exploitation would lead the attacker to steal sensitive information like cookies, login session from sites visited by the victim.",Web Client Internet Explorer/Edge,,5,outgoing,tcp,,6.80,medium,exploit,Internet Explorer
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Microsoft Windows PowerShell ISE Filename Parsing Remote Code Execution Vulnerability Over SMB,6699,Microsoft Windows PowerShell is vulnerable to a filename parsing vulnerability. An attacker may leverage this vulnerability to execute arbitrary code on the victim machine.,DCERPC Services - Client,,"139, 445",outgoing,tcp,,10.00,critical,vulnerability,N/A
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Microsoft Windows PowerShell ISE Filename Parsing Remote Code Execution Vulnerability,6700,Microsoft Windows PowerShell ISE is prone to remote code execution vulnerability when PowerShell ISE incorrectly parses filename. An attacker who successfully exploited the vulnerability could gain the same user rights as the current user.,Web Client Common,,5,outgoing,tcp,,10.00,critical,vulnerability,N/A
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Microsoft Windows Vcf And Contact File Insufficient UI Warning Remote Code Execution Vulnerability,6774,This vulnerability allows remote attackers to execute arbitrary code on vulnerable installations of Microsoft Windows. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.,Web Client Common,,5,outgoing,tcp,,10.00,critical,exploit,N/A
WIN-Q0HITV3HJ6D,,,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,192.168.22.2,12.0.0.563,8,"25/09/2019, 20:52:00 AEST",active,"On, Prevent, 24 rules",Microsoft Internet Explorer Scripting Engine Memory Corruption Vulnerability (CVE-2019-1367),7007,Microsoft Internet Explorer is prone to an unspecified memory corruption vulnerability. Attackers can exploit this issue to execute arbitrary code in the context of the user running the affected application.,Web Client Internet Explorer/Edge,,5,outgoing,tcp,CVE-2019-1367,10.00,critical,exploit,Internet Explorer
```

## Summary

```
Hostname,Platform,Last Agent Comms.,IPS Status,# of IPS Rules
ip-172-31-28-113.ap-southeast-2.compute.internal,Amazon Linux 2 (64 bit) (4.14.123-111.109.amzn2.x86_64),"15/09/2019, 15:02:22 AEST",active,50
WIN-Q0HITV3HJ6D,Microsoft Windows Server 2008 R2 (64 bit) Service Pack 1 Build 7601,"25/09/2019, 20:52:00 AEST",active,24
```

# Contact

* Blog: oznetnerd.com
* Email: will@oznetnerd.com