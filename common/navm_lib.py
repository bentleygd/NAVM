from logging import getLogger
from tempfile import TemporaryFile
from time import sleep

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
            response = request(
                'GET', url, headers=headers, params=params, timeout=5
            )
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
            response = request('GET', url, headers=headers, timeout=5)
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
                'scan_id': scan['id'],
                'scan_name': scan['name'],
                'scan_owner': scan['owner'],
                'scan_status': scan['status'],
                'scan_creation': scan['creation_date'],
                'scan_last_mod': scan['last_modification_date'],
                'scan_start': scan['starttime']
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
    # Logging
    log = getLogger(__name__)
    # Setting scan parameters to be passed during the call to create
    # the scan.
    params = {
        'uuid': scan_data['uuid'],
        'settings': {
            'name': scan_data['name'],
            'description': scan_data['description'],
            'policy_id': scan_data['policy'],
            'enabled': 'true',
            'launch': 'ON_DEMAND',
            'starttime': scan_data['start_time'],
            'targets': scan_data['targets'],

        }
    }
    # Determing which method to use for authentication and setting the
    # appropriate HTTP header.  If no authentication tokens are
    # provided, rasise an exception.
    try:
        if token is not None:
            headers = {'X-Cookie': 'token=' + token}
        elif token is None and keys is not None:
            headers = {'X-ApiKeys:' 'accessKey=%s; secretKey=%s' % (
                keys['access_key'], keys['secret_key']
            )}
        elif token is None and keys is None:
            raise AuthError
    except AuthError:
        log.exception('Authentication tokens not provided.')
        exit(1)
    try:
        # Creating the scan.
        create_response = request(
            'POST', url, params=params, headers=headers, timeout=5
        )
        create_response.raise_for_status()
    except HTTPError:
        log.exception('HTTP error when creating Nessus scan.')
        exit(1)
    except Timeout:
        log.exception('Timeout occurred when creating Nessus scan.')
        exit(1)
    created_scan_data = create_response.json()
    scan_id = created_scan_data['scan']['id']
    start_url = url + '/' + scan_id + '/launch'
    try:
        # Starting the scan.
        start_response = request(
            'POST', start_url, headers=headers, timeout=5
        )
        start_response.raise_for_status()
    except HTTPError:
        log.exception('HTTP error when starting Nessus scan.')
        exit(1)
    except Timeout:
        log.exception('Timeout occurred when starting Nessus scan.')
        exit(1)
    created_scan = start_response.json()[0]
    return created_scan


def nessus_stop_scan(url, scan_id, token=None, keys=None):
    """Stops a running Nessus scan.

    Keyword Arguments:
    url - A string.  The Nessus scan endpoing URL.
    Example: https://scanner.domain.tld:8834/scans/
    scan_id - An integer.  A scan's scan_id value.  This can be found
    in the response from the call to create a Nessus scan.
    token - A string.  Optional value.  This is the session token
    returned by the nessus_session_login_function.
    keys - A dictionary.  Optional value.  These are the keys returned
    by the nessus_get_keys function.

    Returns:
    response_code - An integer.  This is the HTTP response returned by
    the Nessus server.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond.
    AuthError - An exception occurs when invalid credentials are
    provide to the function."""
    # Staring logging.
    log = getLogger(__name__)
    # Determing which method to use for authentication and setting the
    # appropriate HTTP header.  If no authentication tokens are
    # provided, rasise an exception.
    try:
        if token is not None:
            headers = {'X-Cookie': 'token=' + token}
        elif token is None and keys is not None:
            headers = {'X-ApiKeys:' 'accessKey=%s; secretKey=%s' % (
                keys['access_key'], keys['secret_key']
            )}
        elif token is None and keys is None:
            raise AuthError
    except AuthError:
        log.exception('Authentication tokens not provided.')
        exit(1)
    # Setting the scan stop URL with the scan_id passed when the
    # function is called.
    stop_url = url + '/' + scan_id + '/stop'
    try:
        response = request('POST', stop_url, headers=headers, timeout=5)
        response.raise_for_status()
    except HTTPError:
        log.exception('HTTP error when stopping Nessus scan.')
    except Timeout:
        log.exception('Timeout occurred when stopping Nessus scan.')
        exit(1)
    response_code = response.status_code
    # Returning scanner response code to the stop request.
    return response_code


def nessus_html_report(url, scan_id, token=None, keys=None):
    """Creates and downloads a Nessus html report.

    Keyword Arguments:
    url - A string.  The Nessus scan URL.  Exmaple:
    https://nessus.domain.tld:8834/scans
    scan_id - An integer.  The scan_id returned by the call to create a
    scan.
    token - A string, optional.  This value is the session token
    created during authentication to the session endpoint.
    keys - A dictionary, optional.  This value is what is returned by
    the nessus_get_key function.

    Returns:
    scan_report - A temporary file-like object (as created by the
    TemporaryFile class).  This is the data downloaded from the Nessus
    scanner.  Note: this file-like object is utf-8 encoded.

    Rasies:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond.
    AuthError - An exception occurs when invalid credentials are
    provide to the function."""
    # Logging
    log = getLogger(__name__)
    # Determining authentication method.
    try:
        if token is not None:
            headers = {'X-Cookie': 'token=' + token}
        elif token is None and keys is not None:
            headers = {'X-ApiKeys:' 'accessKey=%s; secretKey=%s' % (
                keys['access_key'], keys['secret_key']
            )}
        elif token is None and keys is None:
            raise AuthError
    except AuthError:
        log.exception('Authentication tokens not provided.')
        exit(1)
    # Setting report URL
    create_url = url + '/' + scan_id + '/export'
    # Creating a filter to only report on medium or higher severity
    # vulnerabilities.
    filters = {
        'filter.0.quality': 'neq',
        'filter.0.filter': 'severity',
        'filter.0.value': 'Low',
        'filter.1.quality': 'neq',
        'filter.1.filter': 'severity',
        'filter.1.value': 'None',
        'filter.search_type': 'or'
    }
    # Using hanging indents for the report request for ease of future
    # editing if so desired.
    try:
        create_response = request(
            'POST',
            create_url,
            params={'format': 'CSV', 'filters': filters},
            headers=headers,
            timeout=5
        )
        create_response.raise_for_status()
    except HTTPError:
        log.exception('HTTP error when creating scan report.')
    except Timeout:
        log.exception('Timeout occurred when creating scan report')
    file_id = create_response.json()[0]['file_id']
    status_url = url + '/' + scan_id + '/export/' + file_id + '/status'
    # Looping (potentially forever) and sleeping 60 seconds until the
    # file_status is ready.
    while True:
        try:
            file_status = request(
                'GET', status_url, headers=headers, timeout=5
            )
            file_status.raise_for_status()
        except HTTPError:
            log.exception('HTTP error occurred when obtaining file status.')
            exit(1)
        except Timeout:
            log.exception('Timeout occurred when obtaining file status.')
        if file_status == 'ready':
            break
        else:
            sleep(60)
    download_url = url + '/' + scan_id + '/export/' + file_id + '/download'
    # Getting report data with streaming enabled.
    download_response = request(
        'GET', download_url, headers=headers, timeout=5, stream=True
    )
    scan_report = TemporaryFile()
    for line in download_response.iter_lines():
        scan_report.write(line)
    scan_report.seek(0)
    return scan_report


def nessus_delete_scan(url, scan_id, token=None, keys=None):
    """Deletes a Nessus scan.

    Keyword Arguments:
    url - A string.  The Nessus scan endpoint URL.
    Example: https://nessus.domain.tld:8834/scans/
    scan_id - A string.  The unique identifier of a scan, returned by
    nessus_start_scan.
    token - A string, optional.  This is a session token generated by
    the nessus_get_token.
    keys - A dictionary, optional.  These are the API keys generated by
    nessus_get_keys.

    Returns:
    delete_status - The HTTP status code returned by the call to the
    delete endpoint.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond.
    AuthError - An exception occurs when invalid credentials are
    provide to the function."""
    # Logging
    log = getLogger(__name__)
    # Determining authentication method.
    try:
        if token is not None:
            headers = {'X-Cookie': 'token=' + token}
        elif token is None and keys is not None:
            headers = {'X-ApiKeys:' 'accessKey=%s; secretKey=%s' % (
                keys['access_key'], keys['secret_key']
            )}
        elif token is None and keys is None:
            raise AuthError
    except AuthError:
        log.exception('Authentication tokens not provided.')
        exit(1)
    # Deleting the scan that corresponds to the scan_id value.
    delete_url = url + '/' + scan_id
    try:
        response = request('DELETE', delete_url, headers=headers, timeout=5)
        response.raise_for_status()
    except HTTPError:
        log.exception('Error occurred when deleting scan.')
    except Timeout:
        log.exception('Timeout error occurred when deleting a scan.')
    delete_status = response.status_code
    return delete_status


def nessus_stop_all_scans(url, scan_list, token=None, keys=None):
    """Stops all nessus scans with a status of running.

    Keyword Arugments:
    url - A string.  The Nessus scan URL.  Exampls can be found
    above.
    token - A string.  A session token created by nessus_get_token.
    keys - A dictionary.  A dictionary of API keys created by
    nessus_get_keys.

    Raises:
    AuthError - An exception occurs when invalid credentials are
    provide to the function.
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond."""
    # Logging
    log = getLogger(__name__)
    # Determing authentication method.
    try:
        if token is not None:
            headers = {'X-Cookie': 'token=' + token}
        elif token is None and keys is not None:
            headers = {'X-ApiKeys:' 'accessKey=%s; secretKey=%s' % (
                keys['access_key'], keys['secret_key']
            )}
        elif token is None and keys is None:
            raise AuthError
    except AuthError:
        log.exception('Authentication method not provided.')
        exit(1)
    # Iterating through the scan list, stopping any scan with a status
    # of running.
    stopped_scans = []
    for scan in scan_list:
        if scan['scan_status'] == 'running':
            stop_url = url + '/' + scan['scan_id'] + '/stop'
            try:
                scan_stop = request(
                    'POST', stop_url, headers=headers, timeout=5
                )
                scan_stop.raise_for_status()
            except HTTPError:
                # Note that a non-200 response is benign.
                log.exception('Error occurred when stopping Nessus scan.')
            except Timeout:
                log.exception('Timeout occurred when stopping Nessus scaan.')
            stopped_scans.append(
                {'scan_name': scan['scan_name'], 'owner': scan['owner']}
            )
    return stopped_scans
