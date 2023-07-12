## First things first :-)
I'm developing this plugin in my spare time. If you like this Dynatrace Active Gate Plugin or if it saves you some time and effort. I'm happy to receive a small donation.

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=RUZP3LCKH56CU)

# A Dynatrace Plugin to Monitor SSL Certificates
This active gate remote plugin enhances Dynatrace synthetic monitoring capabilities by checking the expiry date of SSL certificates.
It overcomes the limitation by executing checks against the endpoints that are already configured in Dynatrace's synthetic tests and will post any problems to these synthetic test entities.

## Advantages
Compared to other solutions, this plugin doesn't need any extra configuration for the sites it will check. It reuses the already configured synthetic monitors to perform it's checks, so there is no need to perform extra configuration on the plugin side. Whenever synthetic monitors are added (and potentially tagged) the plugin will check their site's certificate.

Also this plugin will not consume any licenses for custom metrics or DEM points, as it doesn't perform any extra synthetic requests or create metrics.

Additionally the plugin will also fetch any open certificate timeout problems it created earlier and check and update those more frequently. This ensures that problems are automatically closed by the plugin should a expiring certificate get fixed. This allows to have a larger check interval (e.g. every day) but at the same time also ensures that open problems are closed immediately after fixing.

## How to use
To use the plugin you will need an active gate that has the remoteplugin module installed (default for new active gates) and that is able to access the sites you want to monitor.
The plugin works by contacting the Dynatrace API to fetch all configured synthetic montiors. It then determines the hosts that are configured in the synthetic requests and uses this information to perform an SSL validation check.

The plugin requires access to the Dynatrace API so you will need an API key with these permissions:
- APIv2 scopes: event.ingest, event.read, problem.read, metrics.ingest
- APIv1: Read synthetic monitors, locations, and nodes
- ExternalSyntheticIntegration, Create and read synthetic monitors, locations, and nodes

### Configuration Options
These configuration options are available for the plugin:

![config options](./img/configuration.png?s=200)

- Minimum Certificate Validity in Days: the threshold when the plugin should create an alert for a certificate that is about to expire. Please see [Configuration via Tags](#configuration-via-tags) how to override proxy settings per synthetic monitor.
- Time interval for checks: the interval at which the plugin should check certificates (it makes no sense to check every minute). Please note that the interval is calculated based on the current time and not the configuration time. E.g. "every 15 minutes" will mean the check is performed at the full hour, 15 past, 30 past, 45 past the full hour. Likewise every "2 hours" means at 2am, 4am, ... 12am. 
- Select Synthetic Monitors by Tag: Limit the certificate check to synthetic monitors that are tagged with this tag. Only one tag is allowed.
- Consider disabled monitors in checks: when selected the plugin will also perform SSL certificate checks for monitors that are disabled. You can use this option to avoid DEM unit consumption for synthetic checks and still validate certificates.
- Report certificate expiry days as metrics: when enabled the plugin will report the measured expiry days per monitor as metric (metric key is ```threesixty-perf.certificates.daystoexpiry```). Note that custom metrics will consume DDU licenses.
- Dynatrace Tenant UUID to report to: this is the tenant UUID that the plugin will get synthetic monitors from and report to (using the configured API token). Typically this will be the same tenant as the plugin is configured for. Only provide the tenant ID, not the full hostname.
- Dynatrace API token: the API token with the permissions mentioned above
- Proxy and proxy port: when specified the plugin will use the proxy to connect to the target hosts. This is especially helpful for restricted environments where the Active Gate doesn't have full internet access. Please see [Configuration via Tags](#configuration-via-tags) how to override proxy settings per synthetic monitor.

### Problem Events
When the a certificate check fails the plugin will post a problem opening event to Dynatrace (and update is consequently), which contains information about the expiry time and additional certificate information.
As the problem is thereafter updated regulary by the plugin the expiry information will adapt accordingly.

![config options](./img/problem.png?s=200)

## Configuration via Tags
To add more configuration flexibility it is possible to pass per-site settings to the plugin via tags on the Synthetic monitor. (e.g this enables non-admin Dynatrace users with no access to global plugin configuration to somewhat customize their checks). Currently you can override the expiry duration and the proxy configuration that should be used for a SSL endpoint by providing these two tags (case sensitive):

- Key: "SSLCheckExpire" Value: "number" - days to warn before certificate expiration>
- Key: "SSLCheckProxy" Value: "hostname:port" - proxy and port to use for establishing SSL connection

