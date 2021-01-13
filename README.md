# A Dynatrace Remote Plugin to Monitor SSL Certificate Expiry
This active gate remote plugin enhances Dynatrace synthetic monitoring capabilities by checking the expiry date of SSL certificates.
It overcomes the limitation by executing checks against the endpoints that are already configured in Dynatrace's synthetic tests and will post any problems to these synthetic test entities.

## Advantages
Compared to other solutions, this plugin doesn't need any extra configuration for the sites it will check. It reuses the already configured synthetic monitors to perform it's checks, so there is no need to perform extra configuration on the plugin side. Whenever synthetic monitors are added (and potentially tagged) the plugin will check their site's certificate.

Also this plugin will not consume any licenses for custom metrics or DEM points, as it doesn't perform any extra synthetic requests or create metrics.

## How to use
To use the plugin you will need an active gate that has the remoteplugin module installed (default for new active gates) and that is able to access the sites you want to monitor.
The plugin works by contacting the Dynatrace API to fetch all configured synthetic montiors. It then determines the hosts that are configured in the synthetic requests and uses this information to perform an SSL validation check.

The plugin requires access to the Dynatrace API so you will need an API key with these permissions:
- Access problem and event feed, metrics, and topology
- DataIngest, e.g. metrics and events
- Read synthetic monitors, locations, and nodes

### Configuration Options
These configuration options are available for the plugin:

- Minimum Certificate Validity in Days: the threshold when the plugin should create an alert for a certificate that is about to expire
- Time interval for checks: the interval at which the plugin should check certificates (it makes no sense to check every minute). Please note that the interval is calculated based on the current time and not the configuration time. E.g. "every 15 minutes" will mean the check is performed at the full hour, 15 past, 30 past, 45 past the full hour. Likewise every "2 hours" means at 2am, 4am, ... 12am. 
- Select Synthetic Monitors by Tag: Limit the certificate check to synthetic monitors that are tagged with this tag. Only one tag is allowed.
- Dynatrace Tenant UUID to report to: this is the tenant UUID that the plugin will get synthetic monitors from and report to (using the configured API token). Typically this will be the same tenant as the plugin is configured for. Only provide the tenant ID, not the full hostname.
- Dynatrace API token: the API token with the permissions mentioned above

## Further Options
As the plugin as acces to the full certificate it would be rather easy to perform also other checks (e.g. hostname matches). This might be a future addition.