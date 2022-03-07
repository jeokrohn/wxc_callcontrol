"""
base functions for unit tests
"""
import concurrent.futures
import glob
import http.server
import json
import logging
import os
import re
import socketserver
import threading
import time
import urllib.parse
import uuid
import webbrowser
from dataclasses import dataclass
from typing import Optional
from unittest import TestCase

import requests
import yaml
from yaml import safe_load

from integration import Integration
from tokens import Tokens
from webex_simple_api import WebexSimpleApi

log = logging.getLogger(__name__)

__all__ = ['TestCaseWithTokens', 'TestCaseWithLog']


class AdminIntegration(Integration):
    """
    The integration we want to use to get tokens for the test cases
    """
    scopes = ['spark-admin:broadworks_subscribers_write', 'meeting:admin_preferences_write', 'spark:all',
              'meeting:admin_preferences_read', 'analytics:read_all', 'meeting:admin_participants_read',
              'spark-admin:people_write', 'spark:people_write', 'spark:organizations_read',
              'spark-admin:workspace_metrics_read', 'spark-admin:places_read',
              'spark-compliance:team_memberships_write', 'spark:places_read', 'spark-compliance:messages_read',
              'spark-admin:devices_write', 'spark-admin:workspaces_write', 'spark:calls_write',
              'spark-compliance:meetings_write', 'meeting:admin_schedule_write', 'identity:placeonetimepassword_create',
              'spark-admin:organizations_write', 'spark-admin:workspace_locations_read', 'spark:devices_write',
              'spark-admin:broadworks_billing_reports_write', 'spark:xapi_commands', 'spark-compliance:webhooks_read',
              'spark-admin:call_qualities_read', 'spark-compliance:messages_write', 'spark:kms',
              'meeting:participants_write', 'meeting:admin_transcripts_read', 'spark-admin:people_read',
              'spark-compliance:memberships_read', 'spark-admin:resource_groups_read', 'meeting:recordings_read',
              'meeting:participants_read', 'meeting:preferences_write', 'meeting:admin_recordings_read',
              'spark-admin:organizations_read', 'spark-compliance:webhooks_write', 'meeting:transcripts_read',
              'spark:xapi_statuses', 'meeting:schedules_write', 'spark-compliance:team_memberships_read',
              'spark-admin:devices_read', 'meeting:controls_read', 'spark-admin:hybrid_clusters_read',
              'spark-admin:workspace_locations_write', 'spark-admin:telephony_config_read',
              'spark-admin:telephony_config_write', 'spark-admin:broadworks_billing_reports_read',
              'spark-admin:broadworks_enterprises_write', 'meeting:admin_schedule_read', 'meeting:schedules_read',
              'spark-compliance:memberships_write', 'spark-admin:broadworks_enterprises_read', 'spark:calls_read',
              'spark-admin:roles_read', 'meeting:recordings_write', 'meeting:preferences_read',
              'spark-compliance:meetings_read', 'spark-admin:workspaces_read', 'spark:devices_read',
              'spark-admin:resource_group_memberships_read', 'spark-compliance:events_read',
              'spark-admin:resource_group_memberships_write', 'spark-compliance:rooms_read',
              'spark-admin:broadworks_subscribers_read', 'meeting:controls_write', 'meeting:admin_recordings_write',
              'spark-admin:hybrid_connectors_read', 'audit:events_read', 'spark-compliance:teams_read',
              'spark-admin:places_write', 'spark-admin:licenses_read', 'spark-compliance:rooms_write',
              'spark:places_write']

    @property
    def redirect_url(self) -> str:
        return 'http://localhost:6001/redirect'

    def __init__(self):
        super().__init__(
            client_id="C842df6bef07f0674f3cb04397d7cb9c2028b31e722b0bbfc81697ed14c6ed0dc",
            client_secret='2f4008d0b9f7db2d481a8f4aadbb8d54eb381655b7241f9a0296f569ef287f5c')


def get_tokens_from_oauth_flow(integration: Integration) -> Optional[Tokens]:
    """
    Initiate an OAuth flow to obtain new tokens.

    start a local webserver on port 6001 o serve the last step in the OAuth flow

    :param integration: Integration to use for the flow
    :type Integration
    :return: set of new tokens if successful, else None
    :rtype: Tokens
    """

    def serve_redirect():
        """
        Temporarily start a web server to serve the redirect URI at http://localhost:6001/redirect'
        :return: parses query of the GET on the redirect URI
        """

        # mutable to hold the query result
        oauth_response = dict()

        class RedirectRequestHandler(http.server.BaseHTTPRequestHandler):
            # handle the GET request on the redirect URI

            # noinspection PyPep8Naming
            def do_GET(self):
                # serve exactly one GET on the redirect URI and then we are done

                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == '/redirect':
                    log.debug('serve_redirect: got GET on /redirect')
                    query = urllib.parse.parse_qs(parsed.query)
                    oauth_response['query'] = query
                    # we are done
                    self.shutdown(self.server)
                self.send_response(200)
                self.flush_headers()

            @staticmethod
            def shutdown(server: socketserver.BaseServer):
                log.debug('serve_redirect: shutdown of local web server requested')
                threading.Thread(target=server.shutdown, daemon=True).start()

        httpd = http.server.HTTPServer(server_address=('', 6001),
                                       RequestHandlerClass=RedirectRequestHandler)
        log.debug('serve_redirect: starting local web server for redirect URI')
        httpd.serve_forever()
        httpd.server_close()
        log.debug(f'serve_redirect: server terminated, result {oauth_response["query"]}')
        return oauth_response['query']

    state = str(uuid.uuid4())
    auth_url = integration.auth_url(state=state)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # start web server
        fut = executor.submit(serve_redirect)

        webbrowser.open(auth_url)
        # wait for GET on redirect URI and get the result (parsed query of redirect URI)
        try:
            result = fut.result(timeout=120)
        except concurrent.futures.TimeoutError:
            try:
                # post a dummy response to the redirect URI to stop the server
                with requests.Session() as session:
                    session.get(integration.redirect_url, params={'code': 'foo'})
            except Exception:
                pass
            log.warning('Authorization did not finish in time (60 seconds)')
            return

    code = result['code'][0]
    response_state = result['state'][0]
    assert response_state == state

    # get access tokens
    new_tokens = integration.tokens_from_code(code=code)
    if new_tokens is None:
        log.error('Failed to obtain tokens')
        return None
    return new_tokens


def get_tokens() -> Optional[Tokens]:
    """
    Get tokens to run a test

    Tokens are read from a YML file. If needed an OAuth flow is initiated.

    :return: tokens
    :rtype: Tokens
    """

    def yml_path()->str:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testtoken.yml')
        return path

    def write_tokens(*, tokens: Tokens):
        with open(yml_path(), mode='w') as f:
            token_json = tokens.json()
            yaml.dump(json.loads(tokens.json()), f)
        return

    # read tokens from file
    integration = AdminIntegration()
    try:
        with open(yml_path(), mode='r') as f:
            data = safe_load(f)
            tokens = Tokens.parse_obj(data)
    except Exception as e:
        log.debug(f'failed to read tokens from file: {e}')
        tokens = None
    if tokens:
        # validate tokens
        tokens: Tokens
        changed = integration.validate_tokens(tokens=tokens)
        if not tokens.access_token:
            tokens = None
        elif changed:
            write_tokens(tokens=tokens)
    if not tokens:
        # get new tokens via integration if needed
        tokens = get_tokens_from_oauth_flow(integration=integration)
        if tokens:
            tokens.set_expiration()
            write_tokens(tokens=tokens)
    return tokens


class TestCaseWithTokens(TestCase):
    api: WebexSimpleApi
    """
    A test case that required access tokens to run
    """
    @classmethod
    def setUpClass(cls) -> None:
        tokens = get_tokens()
        cls.tokens = tokens
        if tokens:
            cls.api = WebexSimpleApi(tokens=tokens)
        else:
            cls.api = None

    def setUp(self) -> None:
        self.assertTrue(self.tokens and self.api, 'Failed to obtain tokens')


def log_name(prefix: str, test_case_id: str) -> str:
    """
    Get the name for the next REST logfile
    Log file format: '{prefix}_{index:03d}_{test_case_id}'

    :param prefix:
    :param test_case_id:
    :return: path of log file
    """
    # all logs are in the logs directory below the directory of this file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(base_dir, 'logs')

    # get all existing files in that directory, basename only (w/o path)
    logs = glob.glob(os.path.join(base_dir, f'{prefix}_*.log'))
    logs = list(map(os.path.basename, logs))

    # sort files and only look for files matching the log filename structure
    logs_re = re.compile(r'rest_(?P<index>\d{3})_(?P<test_id>.+).log')
    logs.sort()
    logs = [log
            for log in logs
            if logs_re.match(log)]

    # next log file index is based on index of last log file in the list
    if not logs:
        next_log_index = 1
    else:
        m = logs_re.match(logs[-1])
        next_log_index = int(m.group('index')) + 1

    # build the log file name
    log = os.path.join(base_dir,
                       f'{prefix}_{next_log_index:03d}_{test_case_id}.log')
    return log


@dataclass(init=False)
class TestCaseWithLog(TestCaseWithTokens):
    """
    Test case with automatic logging
    """
    log_path: str
    file_log_handler: Optional[logging.Handler]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # this can be reused for other logging to the same file
        self.file_log_handler = None

    def setUp(self) -> None:
        super().setUp()
        print(f'{self.__class__.__name__}.setUp() in TestCaseWithLog.setUp()')
        test_case_id = self.id()
        # enable debug logging on the REST logger
        rest_logger = logging.getLogger('webex_simple_api.rest')
        rest_logger.setLevel(logging.DEBUG)

        # we always want to have REST logging into a file
        self.log_path = log_name(prefix='rest', test_case_id=test_case_id)
        file_handler = logging.FileHandler(filename=self.log_path)
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(fmt='%(asctime)s %(threadName)s %(message)s')
        file_fmt.converter = time.gmtime
        file_handler.setFormatter(file_fmt)
        self.file_log_handler = file_handler

        rest_logger.addHandler(file_handler)

    def tearDown(self) -> None:
        super().tearDown()
        print(f'{self.__class__.__name__}.tearDown() in TestCaseWithLog.teardown()')

        # close REST file handler and remove from REST logger
        rest_logger = logging.getLogger('webex_simple_api.rest')
        rest_logger.removeHandler(self.file_log_handler)

        self.file_log_handler.close()
        self.file_log_handler = None
        self.record_log_handler = None
