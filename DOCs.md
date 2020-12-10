# NAVM Documentation.

<h2>NAVM Core</H2>

The NAVM lib file in the common directory contains the core functions and classes that are utilized by NAVM.

<h3>NAVM Functions</h3>

**nessus_session_login**(url, user_name, password)

This function logs in to the Nessus server session API endpoint and retrieves a session cookie that can  be used for future API calls or to generate and retrieve an API key.  Please note that Nessus scanners have a finite session pool, so good house keeping rules apply and session tokens will need to be destroyed once they are no longer needed.


Keyword arguments:
* url \- A string.  The Nessus URL to call (example: https://server.domain.tld/session/)
* user_name \- A string.  The user name of a user configured on the Nessus server.
* password \- A string.  The password for the user specified in user_name.

Returns:
* token \- A string.  The session cookie/token returned by Nessus that must be used for all Nessus API calls that require authentication.  Note: an API key may be used in lieu of a session token.

Raises:
* HTTPError \- An exception is raised if the Nessus server returns a HTTP error code.
* Timeout \- An exception is rasied if the Nessus server does not respond within 5 seconds.

**Code Example:**
```python
    from common.navm_lib import nessus session login
    from requests import post


    # Getting session token.
    session token = nessus_session_login(
        'https://nessus_scanner.domain.tld:8834/session',
        example_user, # Never store actual credentials in code.
        example_passwd, # Never ever ever store passwords in code.
    )
    # Example of using session token to start a scan.
    # Here we set the session cookie.
    headers = {'X-Cookie': 'token=' + session_token}
    # Nessus scan configuration.
    params = {
        'uuid': template_uuid,
        'settings': {
            'name': name,
            'description': description,
            'enabled': 'true',
            'launch': ON_DEMAND,
            'text_targets': '127.0.0.1'
        }
    }
    scan_url = 'https://nessus_scanner.domain.tld:8834/scans'
    # Requesting the scan.
    scanner_response = post(url, headers=headers, params=params)
```

**nessus_session_logoff**(url, token)

This function destroys a session token (i.e., logs a user off).  This function should be used liberally if there will be a large volue of API calls using session cookies as there is a finite number of session in Nessus scanner.  Please note that API key calls do not have any such limitation. 

Keyword arugments:
* url \- A string.  The Nessus API endpoint to call (example: https://nessus_scanner.domain.tld:8834/session)
* token \- A string.  The session token returned by nessus_session_login.

Returns:
* response_code \- An integer.  The HTTP response code returned by the session endpoint.

Raises:
* HTTPError \- An exception is raised if the Nessus server returns a HTTP error code.
* Timeout \- An exception is rasied if the Nessus server does not respond within 5 seconds.

**Code Example:**
```python
    from common.navm_lib import nessus_session_logoff


    url = 'https://nessus_scanner.domain.tld:8834/session'
    # Calling log off.
    response = nessus_session_logoff(url, token)
    if response = 200:
        print('Succesfully logged off.')
    else:
        print('Error logging off.  Investigate.)
```

**nessus_get_key**(url, token)

This function generates and returns an API key from the Nessus scanner.  This function should only be executed once per user, with the API keys stored in a secure manner.

Keyword Arugments:
* url \- A string.  The keys endpoint of the Nessus scanner.  Example: https://nessus_scanner.domain.tld:8834/session/keys
* token \- A string.  The session token returned by nessus_scanner_login.

Returns:
* api_key \- A dictionary.  The API keys returned by the Nessus server.

Raises:
* HTTPError \- An exception is raised if the Nessus server returns a HTTP error code.
* Timeout \- An exception is rasied if the Nessus server does not respond within 5 seconds.

**Code Example:**
```python
    from common.navm_lib import nessus_get_key
    from requests import post

    key_url = 'https://nessus.domain.tld:8834/session/keys'
    # Getting an API key from a Nessus server.
    keys = nessus_get_key(key_url, token)
    # Logging out of session as we no longer need it.
    session_url = 'https://nessus.domain.tld:8834/session'
    session_log_off = nessus_session_logoff(session_url, token)
    # Configuring scan parameters.
    params = {
        'uuid': template_uuid,
        'settings': {
            'name': name,
            'description': description,
            'enabled': 'true',
            'launch': ON_DEMAND,
            'text_targets': '127.0.0.1'
        }
    }
    scan_url = 'https://nessus.domain.tld:8834/scans'
    # Setting up api-key authentication.
    headers = {'X-ApiKeys:' 'accessKey=%s; secretKey=%s' % (
        keys['access_key'], keys['secret_key']
    )}
    scanner_response = post(scan_url, headers=headers, params=params)
```

**nessus_get_scans**(url, token=None, keys=None, folder=None, last_mod=None)

This function lists all scans that have been created on a Nessus server.  Authentication can occur using either session tokens or an API key.  If the folder value is provided, then only the scans in the given folder ID will be enumerated.  If the last modified date is provided, only the scans modified since the given value will be enumerated.

Keyword arguments:
* url \- A string.  Required value.  The scans endpoint of the Nessus server. Example: https://scanner.domain.tld:8834/scans
* token \- A string.  The session token returned by the nessus_session_login function.  This value is not required if using API keys.
* keys \- A string.  The api keys returned by the nessus_get_key function.  This value is not required if using a session token.
* folder \- An integer.  Optional value.  The folder ID of the scans to retrieve.
* last_mod \- An integer.  Optional value.  The last modified date to use to limit the results to those that have only changed since this time.

Returns:
* scan_list \- A list of dictionaries.  The list of scans from the Nessus server.

Raises:
* HTTPError \- An exception occurs when the Nessus server returns a HTTP error.
* Timeout \- An exception occurs when the Nessus server takes more than five seconds to respond.
* AuthError \- An exception occurs when invalid credentials are provide to the function.

**Code Example:***
```python
    from common.navm_lib import get_nessus_scans, nessus_get_key


    # Listing Nessus URLs.
    auth_url = 'https://nessus.example.tld:8834/keys'
    scan_url = 'https://nessus.exampled.tld:8834/scans'
    token = 'super_secret_string' # Do not store sensitvie data in code
    # Getting a Nesuss API key.  Ideally, this value should be read from a
    # secure location (insted of generating an API key each time).
    api_key = nessus_get_key(auth_url, token)
    # Getting the scan list from the Nessus server.
    scan_list = nessus_get_scans(scan_url, api_key)
    # Printing the scan list.
    for scan in scan_list:
        print(
            'Scan Name:%s Scan Status:%s Last Modified: %s' %
            (scan['scan_name'], scan['scan_status'], scan['last_mod'])
        )
```

**nessus_start_scan**(url, scan_data, token=None, keys=None)

This function creates and starts a Nessus scan.  Authentication is required and can be done with either session keys or API keys.  The returned vaule is a dictionary containing key/value pairs created from the response provided by the Nessus server.

Keyword arugments:
* url \- A string.  The Nessus scan endpoing URL. Example: https://scanner.domain.tld:8834/scans
* scan_data \- A dictionary.  The dictionary containing the necessary field for a scan as noted in the Nessus documentation.
* token \- A string.  Optional value.  This is the session token returned by the Nessus_session_login_function.
* keys \- A string.  Optional value.  These are the keys returned by the nessus_get_keys function.

Returns:
* created_scan \- A dictionary.  This is the response received from the Nessus server.

Raises:
* HTTPError \- An exception occurs when the Nessus server returns an HTTP error.
* Timeout \- An exception occurs when the Nessus server takes more than five seconds to respond.
* AuthError \- An exception occurs when invalid credentials (neither an API key or a session token) are provide to the function.

**Code Example:**
```python
    from common.navm_lib import nessus_get_key, nessus_start_scans

    key_url = 'https://nessus.domain.tld:8834/session/keys'
    # Getting an API key from a Nessus server.
    keys = nessus_get_key(key_url, token)
    # Logging out of session as we no longer need it.
    session_url = 'https://nessus.domain.tld:8834/session'
    session_log_off = nessus_session_logoff(session_url, token)
    # Configuring scan parameters.
    scan_data = {
        'uuid': template_uuid,
        'settings': {
            'name': name,
            'description': description,
            'enabled': 'true',
            'launch': ON_DEMAND,
            'text_targets': '127.0.0.1'
        }
    }
    scan_url = 'https://nessus.domain.tld:8834/scans'
    # Setting up api-key authentication.
    headers = {'X-ApiKeys:' 'accessKey=%s; secretKey=%s' % (
        keys['access_key'], keys['secret_key']
    )}
    nessus_scan_data = nessus_start_scan(scan_url, scan_data, keys)
    print('The scan uuid is:', nessus_scan_data['scan_uuid'])
```

**nessus_stop_scan**(url, scan_id, token=None, keys=None)

This function stops a running Nessus scan that correpsonds to the scan_id argument.  Authentication is required for this function (either a valid session token or API Keys).

Keyword Arguments:
* url \- A string.  The Nessus scan endpoing URL.  Example: https://scanner.domain.tld:8834/scans/
* scan_id \- An integer.  A scan's scan_id value.  This can be found in the response from the call to create a Nessus scan.
* token \- A string.  Optional value.  This is the session token returned by the nessus_session_login_function.
* keys \- A dictionary.  Optional value.  These are the keys returned by the nessus_get_keys function.

Returns:
* response_code \- An integer.  This is the HTTP response returned by the Nessus server.

Raises:
* HTTPError \- An exception occurs when the Nessus server returns a HTTP error.
* Timeout \- An exception occurs when the Nessus server takes more than five seconds to respond.
* AuthError \- An exception occurs when invalid credentials are provide to the function.

**Code Example**
```python
    from configparser import ConfigParser

    from common.navm_lib import nessus_stop_scans


    # Getting Nessus API keys from a configuration.
    config = ConfigParser()
    config.read('example.conf')
    access_key = config['auth']['access']
    secret_key = config['auth']['secret']
    keys = {'access_key': access_key, 'secret_key': secret_key}
    # We use the scan URL as a base.
    url = 'https://nessus.domain.tld:8834/scans'
    # Stopping scan.
    stop_response = nessus_stop_scan(url, 12345, keys=keys)
    print('The stop request returned the following HTTP code:', stop_response)
```

**nessus_html_report**(url, scan_id, token=None, keys=None)

This function exports and downloads a Nessus html report and stores the report in a temporary file-like object.  The data will need to be extracted from the temporary file-like object as it will not persist once the script is complete (the file-like object will be deleted as soon as it is closed).  Authentication is requried for this function.  Note this function will sleep for 60 second intervals until the report is ready to be downloaded, and the report will only include vulnerabilities with a medium severity or higher.

Keyword Arguments:
* url \- A string.  The Nessus scan URL.  Exmaple: https://nessus.domain.tld:8834/scans
* scan_id \- An integer.  The scan_id returned by the call to create a scan.
* token \- A string, optional.  This value is the session token created during authentication to the session endpoint.
* keys \- A dictionary, optional.  This value is what is returned by the nessus_get_key function.

Returns:
* scan_report \- A temporary file-like object (as created by the TemporaryFile class).  This is the data downloaded from the Nessus scanner.

Rasies:
* HTTPError \- An exception occurs when the Nessus server returns a HTTP error.
* Timeout \- An exception occurs when the Nessus server takes more than five seconds to respond.
* AuthError \- An exception occurs when invalid credentials are provide to the function.

**Code Example:**
```python
    from configparser import ConfigParser
    from smtplib import SMTP
    from email.mime.text import MIMEText
    from socket import gethostbyname

    from common.navm_lib import nessus_html_report


    # Getting API keys from a config.
    config = ConfigParser()
    config.read('example.conf')
    access_key = config['auth']['access']
    secret_key = config['auth']['secret']
    keys = {'access_key': access_key, 'secret_key': secret_key}
    # We use the scan URL as a base.
    url = 'https://nessus.domain.tld:8834/scans'
    # Getting scan_report
    scan_report = nessus_html_report(url, '12345', keys=keys)
    mail_body = scan_report.read()
    scan_report.close()
    # Mail configuration.
    msg = MIMEText(mail_body)
    msg['Subject'] = 'Nessus Scan Report'
    msg['From'] = 'Nessus@example.com'
    msg['To'] = 'bob@example.com'
    # Setting up the mailer.
    s = SMTP(gethostbyname('mail_server.example.com'), '25')
    # Sending the report as an email.
    s.sendmail('nessus@example.com', 'bob@example.com', msg.as_string())
```

**nessus_delete_scan***(url, scan_id, token=None, keys=None)

This function deletes a Nessus scan that correpsonds to the provided scan_id.  This function requires authentication (either session tokens or API keys).

Keyword Arguments:
* url \- A string.  The Nessus scan endpoint URL.  Example: https://nessus.domain.tld:8834/scans/
* scan_id \- A string.  The unique identifier of a scan, returned by nessus_start_scan.
* token \- A string, optional.  This is a session token generated by the nessus_get_token.
* keys \- A dictionary, optional.  These are the API keys generated by nessus_get_keys.

Returns:
* delete_status \- The HTTP status code returned by the call to the delete endpoint.

Raises:
* HTTPError \- An exception occurs when the Nessus server returns a HTTP error.
* Timeout \- An exception occurs when the Nessus server takes more than five seconds to respond.
* AuthError \- An exception occurs when invalid credentials are provide to the function.

**Code Example:**
```python
    from common.navm_lib import nessus_delete_scan

    # Getting API keys from a config.
    config = ConfigParser()
    config.read('example.conf')
    access_key = config['auth']['access']
    secret_key = config['auth']['secret']
    keys = {'access_key': access_key, 'secret_key': secret_key}
    # We use the scan URL as a base.
    url = 'https://nessus.domain.tld:8834/scans'
    # Deleting a Nessus scan.
    delete_response = nessus_delete_scan(url, 12345, keys=keys)
    # The response should be 200.  Let's check.
    if delete_response != 200:
        print('Danger Will Robinson!)
    else:
        pass
```

**nessus_stop_all_scans**(url, scan_list, token=None, keys=None)

This function stops all Nessus scans with a status of running.  This is meant to be used in a "break glass in case of emergency" scenario.  This function requires authentication.

Keyword Arguments:
* url \- A string.  The Nessus scan URL.
* token \- A string.  A session token created by nessus_get_token.
* keys \- A dictionary.  A dictionary of API keys created by nessus_get_keys.

Returns:
* Stopped scans \- A list of dictionaries. This is a ist of all the scans that were stopped as a result of executing this function.

Raises:
* AuthError \- An exception occurs when invalid credentials are provide to the function.
* HTTPError \- An exception occurs when the Nessus server returns a HTTP error.
* Timeout \- An exception occurs when the Nessus server takes more than five seconds to respond.

**Code Example:**
```python
    from common.navm_lib import nessus_stop_all_scans


    # Getting API keys from a config.
    config = ConfigParser()
    config.read('example.conf')
    access_key = config['auth']['access']
    secret_key = config['auth']['secret']
    keys = {'access_key': access_key, 'secret_key': secret_key}
    # We use the scan URL as a base.
    url = 'https://nessus.domain.tld:8834/scans'
    # Getting a list of scans.
    scan_list = nessus_get_scans(url, keys=keys)
    # Stopping scans.
    stopped_scans = nessus_stop_all_scans(url, scan_list, keys=keys)
    # Printing each stopped scan.
    print('Here are the stopped scans:')
    for scan in stopped_scans:
        print(scan['scan_name'])
```