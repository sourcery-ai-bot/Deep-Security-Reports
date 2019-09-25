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

# Contact

* Blog: oznetnerd.com
* Email: will@oznetnerd.com