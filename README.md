# Community Playbooks

This is the 6.3 branch of the Splunk SOAR Community Playbooks repository, which contains the default initial playbooks and custom functions for each Splunk SOAR instance. Splunk SOAR was previously known as Phantom. If you are using an older version of Splunk SOAR (or Phantom), then your instance will synchronize with an older branch of this repository, such as [5.4](https://github.com/phantomcyber/playbooks/tree/5.4) or [4.10](https://github.com/phantomcyber/playbooks/tree/4.10)

The Splunk SOAR platform automatically links to the branch of this repository that matches the running Splunk SOAR version. By default, this repository is named **community**, which can be selected as the **Repo** filter to display only these playbooks and custom functions. You can update your content with the **Update from source control** button on the playbook listing page.

## Contributions and support
Playbooks in the community repo are developer-supported. 

If you would like to contribute to the community repo, please follow these steps:

1. Clone the repo and create a new branch
2. Export the playbook from the Splunk SOAR system.
3. Unpack the exported `.tgz` file and add it to the playbooks folder.
4. Open a pull request into the default branch.
5. Ensure the automated tests are resolved and make changes as needed.
6. Upon successfully passing the tests, a Splunk SOAR Community repo maintainer will review your submission.
