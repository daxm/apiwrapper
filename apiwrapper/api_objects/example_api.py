from .apiclasstemplate import APIClassTemplate


class Example(APIClassTemplate):
    """
    An example API object.
    The Example class inherits from the APIClassTemplate all its functions.  They can be modified by building a
    function with the same name here.  For example, the format_data() function inherits from the APIClassTemplate's
    format_data() and then is augmented with the code written here.
    """

    # What extension to the base URL needs to be appended to call this specific API object.
    URL_SUFFIX = '/object/countries'

    def __init__(self, server, **kwargs):
        super().__init__(server, **kwargs)
        logging.debug("In __init__() for Example class.")
        self.parse_kwargs(**kwargs)

    def format_data(self):
        logging.debug("In format_data() for Example class.")
        json_data = {}
        if 'id' in self.__dict__:
            json_data['id'] = self.id
        if 'name' in self.__dict__:
            json_data['name'] = self.name
        return json_data

    # If an API method is not supported you can "skip" the APIClassTemplate's version by adding a "pass" here.
    def post(self):
        logging.info('POST method for API for Example not supported.')
        pass

    def put(self):
        logging.info('POST method for API for Example not supported.')
        pass

    def delete(self):
        logging.info('POST method for API for Example not supported.')
        pass
