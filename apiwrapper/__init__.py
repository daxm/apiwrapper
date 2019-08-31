"""
The apiwrapper __init__.py file is called whenever someone imports the package into their program.
"""

import logging
from .server import Server
from .api_objects import *

logging.debug("In the apiwrapper __init__.py file.")


def __authorship__():
    """In the apiwrapper __authorship__() class method:
***********************************************************************************************************************
This python module was created by Dax Mickelson.
Feel free to send me comments/suggestions/improvements.
Either by email: dmickels@cisco.com or more importantly via a Pull request 
from the github repository: https://github.com/daxm/apiwrapper.
***********************************************************************************************************************
        """
    logging.debug(__authorship__.__doc__)


__authorship__()
