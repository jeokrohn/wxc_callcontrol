from .rest import RestSession,StrOrDict

__all__ = ['ApiChild']


class ApiChild:
    """
    Base class for child APIs of :class:`WebexSimpleAPI`
    """

    def __init__(self, session: RestSession):
        #: REST session
        self.session = session

    def ep(self, path: str):
        """
        endpoint URL for given path

        :param path:
        :type path: str
        :return: endpoint URL
        :rtype: str
        """
        return self.session.ep(path)

    def get(self, *args, **kwargs) -> StrOrDict:
        """
        GET request

        :param args:
        :param kwargs:
        :return:
        """
        return self.session.rest_get(*args, *kwargs)

    def post(self, *args, **kwargs) -> StrOrDict:
        """
        POST request

        :param args:
        :param kwargs:
        :return:
        """
        return self.session.rest_post(*args, **kwargs)

    def put(self, *args, **kwargs) -> StrOrDict:
        """
        PUT request

        :param args:
        :param kwargs:
        :return:
        """
        return self.session.rest_put(*args, **kwargs)

    def delete(self, *args, **kwargs) -> None:
        """
        DELETE request

        :param args:
        :param kwargs:
        """
        self.session.rest_delete(*args, **kwargs)
