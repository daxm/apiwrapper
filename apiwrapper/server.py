"""
This module (server.py) is designed to provide a "toolbox" of tools for interacting with a REST API.
The "toolbox" is the Server class and the "tools" are its methods.
"""

import datetime
import requests
import time
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging

# Disable annoying HTTP warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

""""
The 'requests' package is very chatty on the INFO logging level.  Change its logging threshold sent to logger to
something greater than INFO (i.e. not INFO or DEBUG) will cause it to not log its INFO and DEBUG messages to the
default logger.  This reduces the size of our log files.
"""
logging.getLogger("requests").setLevel(logging.WARNING)


class Server(object):
    """
The Server class has a series of methods, lines that start with "def", that are used to interact with a server's REST
API.  Each method has its own DOCSTRING (like this triple quoted text here) describing its functionality.
    """
    logging.debug("In the Server() class.")

    # The example server API (Cisco's FMC server) has 2 different URL paths for the various API calls.
    API_CONFIG_VERSION = 'api/fmc_config/v1'
    API_PLATFORM_VERSION = 'api/fmc_platform/v1'

    VERIFY_CERT = False
    MAX_PAGING_REQUESTS = 2000

    def __init__(self,
                 host='192.168.45.45',
                 username='admin',
                 password='Admin123',
                 file_logging=None,
                 debug=False,
                 ):
        """
        Instantiate some variables prior to calling the __enter__() method.
        :param host:
        :param username:
        :param password:
        :param file_logging (str): The filename (and optional path) of the output file if a file logger is required,
        None if no file logger is required
        :param debug (bool): True to enable debug logging, default is False
        """

        root_logger = logging.getLogger('')
        root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

        if file_logging:
            formatter = logging.Formatter('%(asctime)s - %(levelname)s:%(filename)s:%(lineno)s - %(message)s',
                                          '%Y/%m/%d-%H:%M:%S')
            file_logger = logging.FileHandler(file_logging)
            file_logger.setFormatter(formatter)
            root_logger.addHandler(file_logger)

        logging.debug("In the Server __init__() class method.")

        self.host = host
        self.username = username
        self.password = password

    def __enter__(self):
        """
        Get a token from the server as well as the Global UUID.  With this information set up the base_url variable.
        :return:
        """
        logging.debug("In the Server __enter__() class method.")
        self.mytoken = Token(host=self.host,
                             username=self.username,
                             password=self.password,
                             verify_cert=self.VERIFY_CERT,
                             )
        self.uuid = self.mytoken.uuid
        self.build_urls()
        return self

    def __exit__(self, *args):
        """
        :param args:
        :return:
        """
        logging.debug("In the Server __exit__() class method.")

    def build_urls(self):
        """
        The FMC APIs appear to use 2 base URLs, depending on what that API is for.  One for "configuration" and the
        other for FMC "platform" things.
        """
        logging.debug("In the Server build_urls() class method.")
        logging.info('Building base to URLs.')
        self.configuration_url = f"https://{self.host}/{self.API_CONFIG_VERSION}"
        self.platform_url = f"https://{self.host}/{self.API_PLATFORM_VERSION}"

    def send_to_api(self, method='', url='', headers='', json_data=None, more_items=[]):
        """
        Using the "method" type, send a request to the "url" with the "json_data" as the payload.
        :param method:
        :param url:
        :param json_data:
        :return:
        """
        logging.debug("In the Server send_to_api() class method.")

        if not more_items:
            self.more_items = []
            self.page_counter = 0
        if headers == '':
            # These values for headers works for most API requests.
            headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.mytoken.get_token()}
        status_code = 429
        response = None
        json_response = None
        try:
            while status_code == 429:
                if method == 'get':
                    response = requests.get(url, headers=headers, verify=self.VERIFY_CERT)
                elif method == 'post':
                    response = requests.post(url, json=json_data, headers=headers, verify=self.VERIFY_CERT)
                elif method == 'put':
                    response = requests.put(url, json=json_data, headers=headers, verify=self.VERIFY_CERT)
                elif method == 'delete':
                    response = requests.delete(url, headers=headers, verify=self.VERIFY_CERT)
                else:
                    logging.error("No request method given.  Returning nothing.")
                    return
                status_code = response.status_code
                if status_code == 429:
                    logging.warning("Too many connections to the Server.  Waiting 30 seconds and trying again.")
                    time.sleep(30)
                if status_code == 401:
                    logging.warning("Token has expired. Trying to refresh.")
                    self.mytoken.access_token = self.mytoken.get_token()
                    headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.mytoken.access_token}
                    status_code = 429
            json_response = json.loads(response.text)
            if status_code > 301 or 'error' in json_response:
                response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logging.error(f"Error in POST operation --> {str(err)}")
            logging.error(f"json_response -->\t{json_response}")
            if response:
                response.close()
            return None
        if response:
            response.close()
        try:
            if 'next' in json_response['paging'] and self.page_counter <= self.MAX_PAGING_REQUESTS:
                self.more_items += json_response['items']
                logging.info(f"Paging:  Offset:{json_response['paging']['offset']}, "
                             f"Limit:{json_response['paging']['limit']}, "
                             f"Count:{json_response['paging']['count']}, "
                             f"Gathered_Items:{self.more_items}")
                self.page_counter += 1
                return self.send_to_api(method=method,
                                        url=json_response['paging']['next'][0],
                                        json_data=json_data,
                                        more_items=self.more_items)
            else:
                json_response['items'] += self.more_items
                self.more_items = []
                return json_response
        except KeyError:
            # Used only when the response only has "one page" of results.
            return json_response


class Token(object):
    """
    The token is the validation object used with the Server.

    """
    logging.debug("In the Token class.")

    MAX_REFRESHES = 3
    TOKEN_LIFETIME = 60 * 30
    API_PLATFORM_VERSION = 'api/fmc_platform/v1'

    def __init__(self, host='192.168.45.45', username='admin', password='Admin123', verify_cert=False):
        """
        Initialize variables used in the Token class.
        :param host:
        :param username:
        :param password:
        :param verify_cert:
        """
        logging.debug("In the Token __init__() class method.")

        self.__host = host
        self.__username = username
        self.__password = password
        self.verify_cert = verify_cert
        self.token_expiry = None
        self.token_refreshes = 0
        self.access_token = None
        self.uuid = None
        self.refresh_token = None
        self.generate_tokens()

    def generate_tokens(self):
        """
        Create new and refresh expired tokens.
        :return:
        """
        logging.debug("In the Token generate_tokens() class method.")

        if self.token_refreshes <= self.MAX_REFRESHES and self.access_token is not None:
            headers = {'Content-Type': 'application/json', 'X-auth-access-token': self.access_token,
                       'X-auth-refresh-token': self.refresh_token}
            url = f'https://{self.__host}/{self.API_PLATFORM_VERSION}/auth/refreshtoken'
            logging.info(
                f"Refreshing tokens, {self.token_refreshes} out of {self.MAX_REFRESHES} refreshes, from {url}.")
            response = requests.post(url, headers=headers, verify=self.verify_cert)
            self.token_refreshes += 1
        else:
            headers = {'Content-Type': 'application/json'}
            url = f'https://{self.__host}/{self.API_PLATFORM_VERSION}/auth/generatetoken'
            logging.info(f"Requesting new tokens from {url}.")
            response = requests.post(url,
                                     headers=headers,
                                     auth=requests.auth.HTTPBasicAuth(self.__username, self.__password),
                                     verify=self.verify_cert,
                                     )
            self.token_refreshes = 0
        self.access_token = response.headers.get('X-auth-access-token')
        self.refresh_token = response.headers.get('X-auth-refresh-token')
        self.token_expiry = datetime.datetime.now() + datetime.timedelta(seconds=self.TOKEN_LIFETIME)

    def get_token(self):
        """
        Check validity of current token.  If needed make a new or resfresh.  Then return access_token.
        :return:
        """
        logging.debug("In the Token get_token() class method.")

        if datetime.datetime.now() > self.token_expiry:
            logging.info("Token Expired.")
            self.generate_tokens()
        return self.access_token
