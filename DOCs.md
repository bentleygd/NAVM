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
    from requests import delete


    url = 'https://nessus_scanner.domain.tld:8834/session'
    # Calling log off.
    response = nessus_session_logoff(url, token)
    if response = 200:
        print('Succesfully logged off.')
    else:
        print('Error logging off.  Investigate.)
```

**get_nessus_key**(url, token)

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
    from common.navm_lib import get_nessus_key
    from requests import post

    key_url = 'https://nessus.domain.tld:8834/session/keys'
    # Getting an API key from a Nessus server.
    api_key = get_nessus_key(key_url, token)
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
    headers = { 
        'X-ApiKeys: ' +
        'accessKey=' + api_key['access_key'] + ';' +
        'secretKey=' + api_key['secret_key']
    }
    scanner_response = post(scan_url, headers=headers, params=params)
```