# NAVM - Nessus Auotmated Vulnerability Management

The purpose of the Nessus Automated Vulnerability Management project is to provide vulnerability management automation to organizations that do not have the budget for Tenable's products that have built-in automation and integration features.  The project has the following features:

* Scan broker.
* Scan self service with authentication.
* User authentication via LDAP.
* A client script that can be utilized to interface with the scan broker.
* Intergration with JIRA for ticketing.

<h2>Third Party Python Package Pre-requisites</h2>

* flask
* flask-mongoengine
* mongoengine
* ldap3
* requests
* mod-wsgi

<h2>Server Requirements</h2>

* MongoDB
* Apache

<h2>Documentation</h2>

Documenation is located [here](https://github.com/bentleygd/NAVM/DOCs.md).