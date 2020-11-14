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
    try:
        response = request('POST', url, params=params, timeout=5)
        response.raise_for_status()
    except HTTPError:
        log.exception('HTTP error returned by the Nessus server.')
    except Timeout:
        log.exception('Connection to Nessus server timed out.')
    token = response.json()[0]['token']
    return token


def nessus_session_logoff(url, token):
    """Logs off from the Nessus server and destroys the session token.
    Please note that Nessus has a limited session pool, so this
    function is critical.  Returns HTTP status code from the Nessus
    server.

    Inputs:
    url - The URL of the session server.  Example:
    https://server.domain:8834/session/destroy
    token - The session token returned by the nessus_login function.

    Outputs:
    response_code - The HTTP response code from the Nessus server.

    Raises:
    HTTPError - An exception occurs when the Nessus server returns a
    HTTP error.
    Timeout - An exception occurs when the Nessus server takes more
    than five seconds to respond."""
    log = getLogger(__name__)
    headers = {'X-Cookie': 'token=' + token}
    try:
        response = request('DELETE', url, headers=headers, timeout=5)
        response.raise_for_status()
    except HTTPError:
        log.exception('HTTP error returned by the Nessus server.')
    except Timeout:
        log.exception('Connection to Nessus server timed out.')
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
    headers = {'X-Cookie': 'token=' + token}
    try:
        response = request('PUT', url, headers=headers, timeout=5)
        response.raise_for_status()
    except HTTPError:
        log.exception('HTTP error returned by the Nessus server.')
    except Timeout:
        log.exception('Connection to Nessus server timed out.')
    api_key = {
        'accessKey': response.json()[0]['accessKey'],
        'secretKey': response.json()[0]['secretKey']
    }
    return api_key
