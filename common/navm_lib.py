from logging import getLogger

from requests import request, HTTPError, Timeout

from NAVM.common.navm_exceptions import AuthError


def nessus_session_login(url, uname, passwd):
    """Logs in to a Nessus server API endpoint, returns session token.

    Keyword Arguments:
    url - str(), The URL of the nessus server endpoint.  Example:
    https://server.domain:8834/session
    uname - str(), The user name used to authenticate to the Nessus server.
    passsword - str(), The password associated with the uname parameter.

    Returns:
    token - str(), The session token returned by the Nessus server.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond."""
    log = getLogger(__name__)
    params = {'username': uname, 'password': passwd}
    # Connecting and authenticating to Nessus.
    try:
        response = request('POST', url, params=params, timeout=5)
        response.raise_for_status()
    # If we get an HTTP error, log it.
    except HTTPError:
        log.exception(
            'HTTP error returned by the Nessus server.  Unable to retrieve' +
            'session token.'
        )
        exit(1)
    # If the connection times out, log it.
    except Timeout:
        log.exception(
            'Connection to Nessus server timed out.  Unable to obtain a' +
            ' session cookie.')
        exit(1)
    token = response.json()[0]['token']
    return token


def nessus_session_logoff(url, token):
    """Logs off from the Nessus server and destroys the session token.
    Please note that Nessus has a limited session pool, so this
    function is critical.  Returns HTTP status code from the Nessus
    server.

    Keyword Arguments:
    url - The session URL of the Nessus scanner.  Example:
    https://nessus_scanner.domain.tld:8834/session
    token - The session token returned by the nessus_login function.

    Returns:
    response_code - The HTTP response code from the Nessus server.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond."""
    log = getLogger(__name__)
    # The value of the X-Cookie header must be the session token
    # previously retrieved by the nessus_session_login function.
    headers = {'X-Cookie': 'token=' + token}
    # Connect to Nessus server and destroy session.
    try:
        response = request('DELETE', url, headers=headers, timeout=5)
        response.raise_for_status()
    # If we get an HTTP error, log it.
    except HTTPError:
        log.exception(
            'HTTP error returned by the Nessus server.  Unable to ' +
            'delete session token.'
        )
    # Log timeouts - this shouldn't occur as a connection to the Nessus
    # server was already established.
    except Timeout:
        log.exception(
            'Connection to Nessus server timed out.  Unable to delete' +
            ' session.')
    response_code = response.status_code
    return response_code


def nessus_get_key(url, token):
    """Retrieves an API key from the Nessus server.

    Keyword Arguments:
    url - The URL to call to obtain an API key. Example:
    https://server.domain:8834/session/keys
    token - The session token returned by the nessus_login function.

    Returns:
    api_key - The API keys returned by the Nessus server.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond."""
    log = getLogger(__name__)
    # The value of the X-Cookie header must be the session token
    # previously retrieved by the nessus_session_login function.
    headers = {'X-Cookie': 'token=' + token}
    try:
        response = request('PUT', url, headers=headers, timeout=5)
        response.raise_for_status()
    # If we get an HTTP error, log it.
    except HTTPError:
        log.exception(
            'HTTP error returned by the Nessus server.  Unable to ' +
            'retrieve an API key.'
        )
        exit(1)
    # If the connection times out, log it.
    except Timeout:
        log.exception(
            'Connection to Nessus server timed out.  Unable to ' +
            'retrieve API key.'
        )
        exit(1)
    api_key = {
        'access_key': response.json()[0]['accessKey'],
        'secret_key': response.json()[0]['secretKey']
    }
    return api_key


def nessus_get_scans(url, token=None, keys=None, folder=None, last_mod=None):
    """Returns a list of scans from the Nessus server.

    Keyword Arguments:
    url - A string.  The /scans endpoint of the Nessus server.
    Example: https://scanner.domain.tld:8834/scans
    token - A string.  The session token returned by the
    nessus_session_login function.  This value is not required if
    using API keys.
    keys - A string.  The api keys returned by the nessus_get_key
    function.  This value is not required if using a session token.
    folder - An integer.  Optional value.  The folder ID of the scans
    to retrieve.
    last_mod - An integer.  Optional value.  The last modified date to
    use to limit the results to those that have only changed since this time.

    Returns:
    scan_list - A list of dictionaries.  The list of scans from the
    Nessus server.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond.
    AuthError - An exception occurs when invalid credentials are
    provide to the function."""
    # Seting logging.
    log = getLogger(__name__)
    # Checking for authentication method.  If no credentials are
    # provided, raise an exception.
    try:
        if token is not None and keys is not None:
            raise AuthError
        elif token is not None and keys is not None:
            session_token = 'X-Cookie: token=' + token
            headers = session_token
        # If API keys are provided, prefer that.
        elif keys is not None:
            api_keys = {
                'X-ApiKeys': 'accessKey=%s; secretKey=%s' % (
                    keys['access_key'], keys['secret_key']
                )
            }
            headers = api_keys
    except AuthError:
        log.exception('No credentials provided for authentication')
        exit(1)
    # Checking for optional keyword vaules
    if folder is not None and last_mod is not None:
        params = {'folder_id': folder, 'last_modification_date': last_mod}
    elif folder is not None and last_mod is None:
        params = {'folder_id': folder}
    elif folder is None and last_mod is not None:
        params = {'last_modification_date': last_mod}
    # Calling the /scans endpoint to retrieve the list of scans.
    if params is not None:
        try:
            response = request('GET', url, headers=headers, params=params)
        # If we get an HTTP error, log it.
        except HTTPError:
            log.exception(
                'HTTP error returned by the Nessus server.  Unable to ' +
                'retrieve the list of scans.'
            )
            exit(1)
        # If the connection times out, log it.
        except Timeout:
            log.exception(
                'Connection to Nessus server timed out.  Unable to ' +
                'retrieve the list of scans.'
            )
            exit(1)
    else:
        try:
            response = request('GET', url, headers=headers)
        # If we get an HTTP error, log it.
        except HTTPError:
            log.exception(
                'HTTP error returned by the Nessus server.  Unable to ' +
                'retrieve the list of scans.'
            )
            exit(1)
        # If the connection times out, log it.
        except Timeout:
            log.exception(
                'Connection to Nessus server timed out.  Unable to ' +
                'retrieve the list of scans.'
            )
            exit(1)
    scan_data = response.json()[0]['scans']
    scan_list = []
    for scan in scan_data:
        scan_list.append(
            {
                scan['id'],
                scan['name'],
                scan['owner'],
                scan['status'],
                scan['creation_date'],
                scan['last_modification_date'],
                scan['starttime']
            }
        )
    return scan_list


def nessus_start_scan(url, scan_data, token=None, keys=None):
    """Creates and starts a Nessus scan.  Returns scan info as a
    dictionary.

    Keyword arugments:
    url - A string.  The Nessus scan endpoing URL.
    Example: https://scanner.domain.tld:8834/scans
    scan_data - A dictionary.  The dictionary containing the necessary
    field for a scan as noted in the Nessus documentation.  See DOCs.md
    for an example.
    token - A string.  Optional value.  This is the session token
    returned by the nessus_session_login_function.
    keys - A string.  Optional value.  These are the keys returned by
    the nessus_get_keys function.

    Returns:
    created_scan - A dictionary.  This is the response received from
    the Nessus server.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond.
    AuthError - An exception occurs when invalid credentials are
    provide to the function."""
    # Stub for the next function.
    pass
