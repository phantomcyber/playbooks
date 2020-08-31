<p align="center">
<img src="https://corelight.com/_nuxt/img/assets/images/logo-corelight-b192e84.png">
</p>
</br>

This is the Corelight Repository for Community Playbooks developed for Splunk Phantom. Any questions please reach out to phantom-playbooks@corelight.com

## Corelight Investigate DNS Alert

This playbook takes a saved search or alert mechanism for DNS from Splunk and pulls the Zeek UID for the alert(s). It then uses logic to identify false positives with the results from DNS answers. Logic then takes DNS IPv4/IPv6 address and looks up Conn logs with matching IP tuples. The services are then used to look for HTTP or SSL traffic and pulls metadata that is interesting. If files are seen during these connections, the file SHA1 is then used to do a file lookup in VirusTotal. If v19+ of Corelight is installed with Suricata, the UID will be used to gather all Suricata alerts for a given flow. Changes and improvements to this playbook are ongoing.


### Installation and Usage

Please reference Splunk's Phantom [documentation](https://docs.splunk.com/Documentation/Phantom/4.9/Install/Overview) for all options on installing Phantom to include:

- AWS
- Virtual Appliance
- RPM
- On systems with limited internet access
- As an unprivileged user

Please use Splunk Phantom's [import](https://docs.splunk.com/Documentation/Phantom/4.9/User/PlaybookList) function to upload playbooks in .tgz format.


## Thanks
These playbooks are created by the community to speed up the analyst response time and potentially decrease false positives. Security should be a team effort!
