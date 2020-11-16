from logging import getLogger

from requests import request, HTTPError, Timeout


def nessus_session_login(url, uname, passwd):
    """Logs in to a Nessus server API endpoint, returns session token.

    Inputs:
    url - str(), The URL of the nessus server endpoint.  Example:
    https://server.domain:8834/session
    uname - str(), The user name used to authenticate to the Nessus server.
    passsword - str(), The password associated with the uname parameter.

    Output:
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

    Inputs:
    url - The session URL of the Nessus scanner.  Example:
    https://nessus_scanner.domain.tld:8834/session
    token - The session token returned by the nessus_login function.

    Outputs:
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


def get_nessus_key(url, token):
    """Retrieves an API key from the Nessus server.

    Inputs:
    url - The URL to call to obtain an API key. Example:
    https://server.domain:8834/session/keys
    token - The session token returned by the nessus_login function.

    Outputs:
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
