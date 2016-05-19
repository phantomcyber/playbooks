# Phantom Cyber Orchestration Playbooks - Repo for Phantom version 1.1

This is the 1.1 release repo for Phantom Community Playbooks.
If you are using Phantom version 1.1, you should update to the latest Phantom release.

As of Phantom version 1.2.265, the community repo is automatically updated to the 1.2 branch to provide you with the latest content.  You can update your content by periodically performing a sync in the Automation playbooks page.

If you are using Phantom version 1.1 after an upgrade from 1.0, if your community repo is still configured for branch 1.0, you should add a second community repo (community11 for example) with the following information.  Do not attempt to delete and re-add the main "community" repo.  If you upgrade to version 1.2, this is not required as your repo configuration will update automatically.

* Repository name: community11
* URI: https://github.com/phantomcyber/playbooks.git
* Branch Name: 1.1
* Read Only: Checked