"""
Misc methods/functions that are used by the apiwrapper package's modules.
"""

import re
import json
import logging

logging.debug(f"In the {__name__} module.")


def syntax_correcter(value, permitted_syntax="""[.\w\d_\-]""", replacer='_'):
    """
    Check 'value' for invalid characters (identified by 'permitted_syntax') and replace them with 'replacer'.
    :param value:  String to be checked.
    :param permitted_syntax: (optional) regex of allowed characters.
    :param replacer: (optional) character used to replace invalid characters.
    :return: Modified string with "updated" characters.
    """
    logging.debug("In syntax_correcter() helper_function.")
    new_value = ''
    for char in range(0, len(value)):
        if not re.match(permitted_syntax, value[char]):
            new_value += replacer
        else:
            new_value += value[char]
    return new_value


def mocked_requests_get(**kwargs):
    """
    Use to "mock up" a response from using the "requests" library to avoid actually using the "requests" library.
    :param kwargs: 
    :return: 
    """
    logging.debug("In mocked_requests_get() helper_function.")

    class MockResponse:
        def __init__(self, **kwargs):
            logging.debug("In MockResponse __init__ method.")
            self.text = json.dumps(kwargs['text'])
            self.status_code = kwargs['status_code']

        def close(self):
            logging.debug("In MockResponse close method.")
            return True
    return MockResponse(**kwargs)
