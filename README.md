Retrieve a list of domains from AWS Route53, Azure, or GoDaddy.

The script retrieves the following information:

* Domain name
* Registrar (AWS, Azure, or GoDaddy)
* Creation date / time
* Expiration date / time
* Whether the domain is expired
* If not expired, days remaining until expiration
* Whether auto-renew is enabled
* Whether privacy features are enabled
* The IP the domain currently resolves to, if any

The script retrieves other elements of information if the service in question provides them. These include:

* Domain ID (generally an internally-relevant identification number or string)
* Registrant contact information
* Whether transfer lock is enabled
* DNS provider
* Nameservers

Skeleton Namecheap functions exist but are not built out.

When provided with a Slack webhook URL, the script posts a message to Slack including the domain names and some pertinent information.

**Usage**

Include API keys in the configuration file and pass the configuration file location to `get_domains.py`:

`python get_domains.py /path/to/config`

The script automatically attempts to retrieve domain information for every provider with information included in the configuration file.

To control what providers the script queries, you can specify them on the command line:

`python get_domains.py -p aws /path/to/config` # Query only AWS

`python get_domains.py -p aws -p azure /path/to/config` # Query AWS and Azure

This setting overrides the configuration file, so even if the configuration file includes authentication material for all providers, the script only queries those listed.

By default, the script does not display information about expired domains to Slack or the terminal (though it includes expired domains in CSV and JSON output). To include expired domains in the output, pass the `-x / --show-expired` flag:

`python get_domains.py -p godaddy -x /path/to/config`

To save output as CSV or JSON, pass the `-c / --csv-file` or `-j / --json-file` arguments along with the desired filename.

`python get_domains.py -c domains.csv -j domains.json`

The CSV and JSON files contain all retrieved information for each domain, whereas the Slack messages and terminal output include specific pieces of information.


