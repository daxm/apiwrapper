import logging
# Each API Class needs to be imported.
from .example_api import Example

logging.debug("In the api_objects __init__.py file.")

# Each API Class needs to be identified here so that it can be referenced directly via apiwrapper.<Class>.
__all__ = [
'Example',
]
