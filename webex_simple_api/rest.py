"""
REST session for Webex API requests
"""
import json
import logging
import time
import uuid
from collections.abc import Generator
from io import TextIOBase, StringIO
from typing import List, Union, Tuple, Type
from urllib.parse import parse_qsl

import backoff
from pydantic import BaseModel, ValidationError
from requests import HTTPError, Response, Session

from tokens import Tokens
from .base import ApiModel

__all__ = ['SingleError', 'ErrorDetail', 'RestError', 'StrOrDict', 'RestSession', 'dump_response']

log = logging.getLogger(__name__)


class SingleError(BaseModel):
    description: str
    code: int


class ErrorDetail(ApiModel):
    """
    Representation of error details in the body of an HTTP error response from Webex
    """
    message: str  #: error message
    errors: List[SingleError]  #: list of errors; typically has a single entry
    tracking_id: str  #: tracking ID of the request

    @property
    def description(self) -> str:
        """
        error description

        """
        return self.errors and self.errors[0].description or ''

    @property
    def code(self) -> int:
        """
        error code

        """
        return self.errors and self.errors[0].code or 0


class RestError(HTTPError):
    """
    A REST error
    """

    def __init__(self, msg: str, response: Response):
        super().__init__(msg, response=response)
        # try to parse the body of the API response
        try:
            self.detail = ErrorDetail.parse_obj(json.loads(response.text))
        except (json.JSONDecodeError, ValidationError):
            self.detail = None

    @property
    def description(self) -> str:
        """
        error description

        """
        return self.detail and self.detail.description or ''

    @property
    def code(self) -> str:
        """
        error code

        """
        return self.detail and self.detail.code or 0


def dump_response(response: Response, file: TextIOBase = None, dump_log: logging.Logger = None) -> None:
    """
    Dump response to log file

    :param response: HTTP request response
    :param file: stream to dump to
    :type file: TextIOBase
    :param dump_log: logger to dump to
    :type dump_log: logging.Logger
    :return: None
    """
    if not log.isEnabledFor(logging.DEBUG):
        return
    dump_log = dump_log or log
    output = file or StringIO()

    # dump response objects in redirect history
    for h in response.history:
        dump_response(response=h, file=output)

    print(f'Request {response.status_code}[{response.reason}]: '
          f'{response.request.method} {response.request.url}', file=output)

    # request headers
    for k, v in response.request.headers.items():
        if k == 'Authorization':
            v = 'Bearer ***'
        print(f'  {k}: {v}', file=output)

    # request body
    request_body = response.request.body
    if request_body:
        print('  --- body ---', file=output)
        ct = response.request.headers.get('content-type').lower()
        if ct.startswith('application/json'):
            for line in json.dumps(json.loads(request_body), indent=2).splitlines():
                print(f'  {line}', file=output)
        elif ct.startswith('application/x-www-form-urlencoded'):
            for k, v in parse_qsl(request_body):
                print(f'  {k}: {"***" if k == "client_secret" else v}',
                      file=output)
        else:
            print(f'  {request_body}', file=output)

    print(f' Response', file=output)
    # response headers
    for k in response.headers:
        print(f'  {k}: {response.headers[k]}', file=output)
    body = response.text
    # dump response body
    if body:
        print('  ---response body ---', file=output)
        try:
            body = json.loads(body)
            if 'access_token' in body:
                # mask access token
                body['access_token'] = '***'
            body = json.dumps(body, indent=2)
        except json.JSONDecodeError:
            pass
        for line in body.splitlines():
            print(f'  {line}', file=output)
    print(f' ---- end ----', file=output)
    if file is None:
        dump_log.debug(output.getvalue())


def _giveup_429(e: RestError) -> bool:
    """
    callback for backoff on REST requests

    :param e: latest exception
    :return: True -> break the backoff loop
    """
    response = e.response
    response: Response
    if response.status_code != 429:
        # Don't retry on anything other than 429
        return True

    # determine how long we have to wait
    retry_after = int(response.headers.get('Retry-After', 5))

    # never wait more than the defined maximum
    retry_after = min(retry_after, 20)
    time.sleep(retry_after)
    return False


StrOrDict = Union[str, dict]


class RestSession(Session):
    BASE = 'https://webexapis.com/v1'
    """
    REST session

    A REST session:
        * includes an Authorization header in reach request
        * implements retries on 429
        * loads JSON data
    """

    def __init__(self, tokens: Tokens):
        super().__init__()
        self._tokens = tokens

    def ep(self, path: str = None):
        path = path and f'/{path}' or ''
        return f'{self.BASE}{path}'

    @backoff.on_exception(backoff.constant, RestError, interval=0, giveup=_giveup_429)
    def _request_w_response(self, method: str, *args, headers=None,
                            **kwargs) -> Tuple[Response, StrOrDict]:
        """
        low level API REST request with support for 429 rate limiting

        :param method: HTTP method
        :type method: str
        :param args:
        :type args:
        :param headers: prepared headers for request
        :type headers: Optional[dict]
        :param kwargs: additional keyward args
        :type kwargs: dict
        :return: Tuple of response object and body. Body can be text or dict (parsed from JSON body)
        :rtype:
        """
        headers = headers or dict()
        headers.update({'Authorization': f'Bearer {self._tokens.access_token}',
                        'Content-type': 'application/json;charset=utf-8',
                        'TrackingID': f'WXC_SIMPLE_{uuid.uuid4()}'})
        with self.request(method, *args, headers=headers, **kwargs) as response:
            dump_response(response)
            try:
                response.raise_for_status()
            except HTTPError as error:
                # create a RestError based on HTTP error
                error = RestError(error.args[0], response=error.response)
                raise error
            # get response body as text pr dict (parsed JSON)
            ct = response.headers.get('Content-Type')
            if not ct:
                data = ''
            elif ct.startswith('application/json') and response.text:
                data = response.json()
            else:
                data = response.text
        return response, data

    def _request(self, method: str, *args, **kwargs) -> StrOrDict:
        """
        low level API request only returning the body

        :param method: HTTP method
        :type method: str
        :param args:
        :type args:
        :param headers: prepared headers for request
        :type headers: Optional[dict]
        :param kwargs: additional keyward args
        :type kwargs: dict
        :return: body. Body can be text or dict (parsed from JSON body)
        :rtype: Unon
        """
        _, data = self._request_w_response(method, *args, **kwargs)
        return data

    def rest_get(self, *args, **kwargs) -> StrOrDict:
        """
        GET request

        :param args:
        :param kwargs:
        :return:
        """
        return self._request('GET', *args, **kwargs)

    def rest_post(self, *args, **kwargs) -> StrOrDict:
        """
        POST request

        :param args:
        :param kwargs:
        :return:
        """
        return self._request('POST', *args, **kwargs)

    def rest_put(self, *args, **kwargs) -> StrOrDict:
        """
        PUT request

        :param args:
        :param kwargs:
        :return:
        """
        return self._request('PUT', *args, **kwargs)

    def rest_delete(self, *args, **kwargs) -> None:
        """
        DELETE request

        :param args:
        :param kwargs:
        """
        self._request('DELETE', *args, **kwargs)

    def follow_pagination(self, *, url: str, model: Type[ApiModel],
                          params=None, **kwargs) -> Generator[ApiModel, None, None]:
        """
        Handling RFC5988 pagination of list requests. Generator of parsed objects

        :param url: start url for 1st GET
        :param model: data type to return
        :param params: URL parameters
        :return: yields parsed objects
        """
        while url:
            log.debug(f'{self}.pagination: getting {url}')
            response, data = self._request_w_response('GET', url, params=params, **kwargs)
            # params only in first request. In subsequent requests we rely on the completeness of the 'next' URL
            params = None
            # try to get the next page (if present)
            try:
                url = str(response.links['next']['url'])
            except KeyError:
                url = None
            # return all items
            items = data.get('items', [])
            for item in items:
                yield model.parse_obj(item)
