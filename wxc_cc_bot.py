#!/usr/bin/env python3
"""
A simple bot demonstrating some of the capabilities of the Webex Calling call control APIs
"""
import datetime
import json
import logging
import os
import threading
import urllib.parse
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import wraps
from io import StringIO
from itertools import chain
from typing import Optional, List, Dict

import flask
import pydantic
import pytz
import redis
import requests
import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from webexteamsbot import TeamsBot
from webexteamssdk import Message, WebexTeamsAPI

import ngrokhelper
from tokens import Tokens
from wx_simple_api import WebexSimpleApi, TelephonyEvent, WebHookResource, dump_response

log = logging.getLogger(__name__)

load_dotenv()

LOCAL_BOT_PORT = 6001


# TODO: redis implementation
#   garbage collection on flow-keys in redis
#       * triggered when a new flow is initiated
#       * iterate over all flow keys
#       * delete the ones which are too old


class UserContext(BaseModel):
    """
    User context. For each user we need to keep track of the tokens obtained for that user
    """
    user_id: str
    tokens: Tokens


class TokenManager(ABC):
    """
    Token manager consolidates all functions around tokens.
    * registering a new OAuth flow
    * processing the code at the end of the flow to obtain tokens
    * storing user contexts
    * providing access to user contexts
    """

    def __init__(self, bot_token: str, integration: 'Integration', **kwargs):
        self.integration = integration
        self.bot_token = bot_token

    @abstractmethod
    def close(self):
        ...

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @abstractmethod
    def start_flow(self, *, user_id: str) -> str:
        """
        Register OAuth flow for a user
        :param user_id:
        :return: flow id
        """
        ...

    @abstractmethod
    def process_redirect(self, *, flow_id: str, code: str) -> str:
        """
        Process redirect at end of OAuth flow. New tokens are stored in user context
        :param flow_id:
        :param code:
        :return: text for HTTP response
        """
        ...

    @abstractmethod
    def get_user_context(self, *, user_id: str) -> Optional[UserContext]:
        """
        Get user context for given user_id
        :param user_id:
        :return:
        """
        ...

    def set_user_context(self, *, user_id: str, user_context: UserContext = None):
        """
        Add user context to cache or clear it from cache (user_context==None)
        :param user_context:
        :return:
        """
        ...

    def register_redirect(self, *, flask: flask.Flask):
        """
        Reguser /redirect endpoint for OAuth flows
        :return:
        """
        # register /redirect endpoint
        flask.add_url_rule(rule='/redirect', endpoint='redirect', view_func=self.redirect, methods=('GET',))

    def redirect(self):
        """
        view function for GET on /redirect
        Get code and state (flow id) from URL and set event on the registered flow
        :return:
        """
        # get code and flow id from URL
        query = urllib.parse.parse_qs(flask.request.query_string.decode())
        code = query.get('code', [None])[0]
        flow_id = query.get('state', [None])[0]

        if not all((code, flow_id)):
            return ''
        return self.process_redirect(flow_id=flow_id, code=code)

    def token_refresh(self, *, tokens) -> bool:
        """
        try to refresh the tokens
        :param tokens:
        :return:
        """
        return self.integration.validate_tokens(tokens)


class RedisTokenManager(TokenManager):
    """
    Token Maager using Redis as backend
    """
    FLOW_SET = 'flows'
    USER_KEY_PREFIX = 'user'
    USER_SET = 'users'

    def flow_key(self, *, flow_id: str) -> str:
        """
        A key for a flow
        :param flow_id:
        :return:
        """
        return f'{self.FLOW_SET}-{flow_id}'

    def user_key(self, *, user_id) -> str:
        """
        A redis key for a given user ID
        :param user_id:
        :return:
        """
        return f'{self.USER_KEY_PREFIX}-{user_id}'

    class FlowState(BaseModel):
        """
        keep track of a pending OAuth flow. For each flow we keep track of the creation time. This time is used to
        garbage collect old flows if needed
        """
        user_id: str
        created: datetime.datetime = Field(default_factory=lambda: datetime.datetime.utcnow().replace(tzinfo=pytz.UTC))

    def __init__(self, bot_token: str, integration: 'Integration', redis_host: str = None, redis_url: str = None):
        """
        set up token Manager
        :param bot_token: bot access token. Required to be able to send responses to the user
        :type bot_token: str
        :param integration: OAuth integration. Used to call the respective endpoints to obtain/refresh tokens
        :type integration:  Integration
        :param redis_host: Redis host, Redis host takes precedence over Redis URL
        :type redis_host: str
        :param redis_url: Redis URL, Redis host takes precedence over Redis URL
        :type redis_url: str
        """
        super().__init__(bot_token=bot_token, integration=integration)
        if redis_host:
            redis_url = f'redis://{redis_host}'
            log.debug(f'Setting up redis, host: {redis_host} ->url: {redis_url}')
        url = urllib.parse.urlparse(redis_url)
        ssl = url.scheme == 'rediss'
        log.debug(f'Setting up redis, url: {redis_url}, ssl: {ssl}')
        self.redis = redis.Redis(host=url.hostname, port=url.port or 6379, username=url.username, password=url.password,
                                 ssl=ssl, ssl_cert_reqs=None)
        # Verify Redis operation
        log.debug('get(test)')
        self.redis.get('test')
        log.debug('got(test) --> redis is alive')

    def close(self):
        # close redis connection
        if self.redis:
            self.redis.close()
            self.redis = None

    def _flow_maintenance(self):
        """
        Garbage collection on existing flows
        :return:
        """
        now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        # iterate over all flows
        for flow_key in self.redis.smembers(self.FLOW_SET):
            flow_state = self._get_flow_state(flow_key=flow_key)
            if not flow_state or ((now - flow_state.created).total_seconds() > 300):
                # candidate for deletion
                log.debug(f'garbage collection for flow {flow_key}: {flow_state}')
                self.redis.srem(self.FLOW_SET, flow_key)
                if flow_state:
                    self.redis.delete(flow_key)
                # if
            # if not
        # for
        return

    def _get_flow_state(self, *, flow_key: str) -> Optional[FlowState]:
        """
        Get parsed flow state from redis
        :param flow_key:
        :return:
        """
        flow_state_str = self.redis.get(flow_key)
        if not flow_state_str:
            return None
        try:
            flow_state = RedisTokenManager.FlowState.parse_obj(json.loads(flow_state_str))
        except (json.JSONDecodeError, pydantic.PydanticTypeError, pydantic.ValidationError) as e:
            log.warning(f'failed to parse state for flow key {flow_key}: {e}')
            return None
        return flow_state

    def start_flow(self, *, user_id: str) -> str:
        """
        Register OAuth flow for a user
        :param user_id:
        :return: flow id
        """
        flow_id = str(uuid.uuid4())
        flow_key = self.flow_key(flow_id=flow_id)
        flow_state = RedisTokenManager.FlowState(user_id=user_id).json()
        log.debug(f'start_flow: set({flow_key}, {flow_state})')
        self.redis.set(flow_key, flow_state)
        self.redis.sadd(self.FLOW_SET, flow_key)
        return flow_id

    def process_redirect(self, *, flow_id: str, code: str) -> str:
        """
        Process redirect at end of OAuth flow. New tokens are stored in user context
        :param flow_id:
        :param code:
        :return:
        """
        flow_key = self.flow_key(flow_id=flow_id)
        flow_state = self._get_flow_state(flow_key=flow_key)
        if not flow_state:
            log.warning(f'process_redirect({flow_id}, {code}): failed to get state')
            return f'unable to get state for flow'

        # delete flow from redis
        self.redis.delete(flow_key)
        self.redis.srem(self.FLOW_SET, flow_key)

        # get token for code
        try:
            tokens = self.integration.tokens_from_code(code=code)
        except requests.HTTPError as e:
            log.error(f'process_redirect({flow_id}, {code}): failed to get tokens, {e}')
            return f'failed to get tokens'
        tokens.set_expiration()

        # use the new tokens to get identity of authenticated user
        with WebexSimpleApi(tokens=tokens) as api:
            me = api.people.me()
        if me.person_id != flow_state.user_id:
            log.warning(f'process_redirect({flow_id}, {code}): tokens for wrong user: {me.emails[0]}')
            api = WebexTeamsAPI(access_token=self.bot_token)
            api.messages.create(toPersonId=flow_state.user_id,
                                text=f'tokens for wrong user: {me.emails[0]}')

            return f'tokens for wrong user: {me.emails[0]}'
        # store user context (tokens) in redis
        user_context = UserContext(user_id=flow_state.user_id, tokens=tokens)
        log.debug(f'process_redirect({flow_id}, {code}): store context')
        self.set_user_context(user_id=user_context.user_id, user_context=user_context)

        # inform user about successful authentication
        api = WebexTeamsAPI(access_token=self.bot_token)
        api.messages.create(toPersonId=flow_state.user_id,
                            text=f'Successfully authenticated. Access '
                                 f'token valid until {tokens.expires_at}')
        return 'Authenticated'

    def set_user_context(self, *, user_id: str, user_context: UserContext = None):
        """
        Store user context in redis
        :param user_context:
        :return:
        """
        redis_key = self.user_key(user_id=user_id)
        if user_context is None:
            log.debug(f'set_user_context: remove {redis_key}')
            self.redis.delete(redis_key)
            self.redis.srem(self.USER_SET, redis_key)
        else:
            user_context_json = user_context.json()
            log.debug(f'set_user_context: {redis_key}->{user_context_json}')
            self.redis.set(redis_key, user_context_json)
            self.redis.sadd(self.USER_SET, redis_key)

    def get_user_context(self, *, user_id: str) -> Optional[UserContext]:
        """
        Get user context for given user_id
        :param user_id:
        :return:
        """
        redis_key = self.user_key(user_id=user_id)
        log.debug(f'get_user_context: get({redis_key})')
        user_context_json = self.redis.get(redis_key)
        log.debug(f'get_user_context: got({redis_key}) -> {user_context_json}')
        if not user_context_json:
            return None
        try:
            user_context = UserContext.parse_obj(json.loads(user_context_json))
        except Exception as e:
            log.warning(f'get_user_context({user_id}): failed to parse JSON, {e}')
            return None

        def refresh():
            """
            Refresh the access token in the user context.
            :return:
            :rtype:
            """
            log.debug(f'Token refresh for {user_id}')
            refreshed = self.token_refresh(tokens=user_context.tokens)
            if refreshed:
                log.debug(f'got new tokens for {user_id}')
                self.set_user_context(user_id=user_context.user_id, user_context=user_context)
            if not user_context.tokens.access_token:
                log.error(f'No access token for {user_id}')

        if user_context.tokens.needs_refresh:
            if user_context.tokens.remaining < 0 or not user_context.tokens.access_token:
                # need immediate refresh
                refresh()
            else:
                # good for now but we need new tokens "soon": schedule a task
                log.debug(f'Initiate refresh of tokens for {user_id}')
                threading.Thread(target=refresh).start()
        return user_context


class YAMLTokenManager(TokenManager):
    """
    A TokenManager using a local YAML file to store user contexts
    """
    def __init__(self, bot_token: str, integration: 'Integration', yml_base: str):
        super().__init__(bot_token=bot_token, integration=integration)
        self.yml_path = os.path.join(os.getcwd(), f'{yml_base}.yml')
        self._user_context: Dict[str, UserContext] = dict()
        self._flows: Dict[str, str] = dict()
        try:
            with open(self.yml_path, 'r') as file:
                data = yaml.safe_load(file)
        except FileNotFoundError:
            data = {}
        for user_id, context in data.items():
            self._user_context[user_id] = UserContext.parse_obj(context)

    def close(self):
        # nothing to do here
        pass

    def start_flow(self, *, user_id: str) -> str:
        """
        Register OAuth flow for a user
        :param user_id:
        :return: flow id
        """
        flow_id = str(uuid.uuid4())
        self._flows[flow_id] = user_id
        return flow_id

    def process_redirect(self, *, flow_id: str, code: str) -> str:
        """
        Process redirect at end of OAuth flow. New tokens are stored in user context
        :param flow_id:
        :param code:
        :return:
        """
        user_id = self._flows.pop(flow_id, None)
        if user_id is None:
            log.warning(f'unknown flow id: {flow_id}')
        try:
            tokens = self.integration.tokens_from_code(code=code)
        except requests.HTTPError as e:
            log.error(f'failed to get tokens: {e}')
            return f'failed to get tokens'
        tokens.set_expiration()
        with WebexSimpleApi(tokens=tokens) as api:
            me = api.people.me()
        if me.person_id != user_id:
            log.warning(f'process_redirect({flow_id}, {code}): tokens for wrong user: {me.user_name}')
            api = WebexTeamsAPI(access_token=self.bot_token)
            api.messages.create(toPersonId=user_id,
                                text=f'tokens for wrong user: {me.user_name}')

            return f'tokens for wrong user: {me.user_name}'
        # store user context (tokens) in redis
        user_context = UserContext(user_id=user_id, tokens=tokens)
        log.debug(f'process_redirect({flow_id}, {code}): store context')
        self.set_user_context(user_id=user_context.user_id, user_context=user_context)

        # inform user about successful authentication
        api = WebexTeamsAPI(access_token=self.bot_token)
        api.messages.create(toPersonId=user_id,
                            text=f'Successfully authenticated. Access '
                                 f'token valid until {tokens.expires_at}')
        return 'Authenticated'

    def set_user_context(self, *, user_id: str, user_context: UserContext = None):
        """
        Store user context in redis
        :param user_context:
        :return:
        """
        if user_context is None:
            log.debug(f'set_user_context: remove {user_id}')
            self._user_context.pop(user_id, None)
        else:
            self._user_context[user_id] = user_context
        # commit to file
        data = {k: json.loads(v.json()) for k, v in self._user_context.items()}
        with open(self.yml_path, mode='w') as file:
            yaml.dump(data, file)

    def get_user_context(self, *, user_id: str) -> Optional[UserContext]:
        """
        Get user context for given user_id
        :param user_id:
        :return:
        """
        context = self._user_context.get(user_id)
        return context


@dataclass
class Integration:
    """
    an OAuth integration
    """
    client_id: str
    client_secret: str
    # TODO: find out which scopes are actually required
    scopes = 'spark:calls_write spark:all spark:kms spark:calls_read spark-admin:telephony_config_read ' \
             'spark-admin:telephony_config_write spark-admin:people_read'
    # scopes = 'spark:people_read spark:calls_write spark:kms spark:calls_read spark-admin:telephony_config_read'
    auth_service = 'https://webexapis.com/v1/authorize'
    token_service = 'https://webexapis.com/v1/access_token'

    @property
    def redirect_url(self) -> str:
        """
        Obtain redirect URI. Either on Heroku or localhost:6001
        :return: redirect URL
        :rtype: str
        """
        # redirect URL is either local or to heroku
        heroku_name = os.getenv('HEROKU_NAME')
        if heroku_name:
            return f'https://{heroku_name}.herokuapp.com/redirect'
        return 'http://localhost:6001/redirect'

    def auth_url(self, *, state: str) -> str:
        """
        Get the URL to start an OAuth flow for the integration
        :param state: state in redirect URL
        :type state: str
        :return: URL to start the OAuth flow
        :rtype: str
        """
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_url,
            'scope': self.scopes,
            'state': state
        }
        full_url = f'{self.auth_service}?{urllib.parse.urlencode(params)}'
        return full_url

    def tokens_from_code(self, *, code: str) -> Tokens:
        """
        Get a new set of tokens from code at end of OAuth flow
        :param code: code obtained at end of SAML 2.0 OAuth flow
        :type code: str
        :return: new tokens
        :rtype: Tokens
        """
        url = self.token_service
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_url
        }
        with requests.Session() as session:
            response = session.post(url=url, data=data)
            dump_response(response, dump_log=log)

        response.raise_for_status()
        json_data = response.json()
        tokens = Tokens.parse_obj(json_data)
        return tokens

    def validate_tokens(self, tokens: Tokens) -> bool:
        """
        Validate tokens if remaining life time is to small then try to get a new access token
        using the existing refresh token.
        If no new access token can be obtained using the refresh token then the access token is set to None
        and True is returned
        :param tokens:
        :return: Indicate if tokens have been changed
        """
        if tokens.needs_refresh:
            log.debug(f'Getting new access token, valid until {tokens.expires_at}, remaining {tokens.remaining}')
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': tokens.refresh_token
            }
            try:
                url = self.token_service
                with requests.Session() as session:
                    with session.post(url=url, data=data) as response:
                        dump_response(response=response, dump_log=log)
                        response.raise_for_status()
                        json_data = response.json()
            except requests.HTTPError:
                tokens.access_token = None
            else:
                new_tokens = Tokens.parse_obj(json_data)
                new_tokens: Tokens
                new_tokens.set_expiration()
                tokens.update(new_tokens)
                return True
        return False


def catch_exception(f):
    """
    Wrapper to catch and log exceptions which led to termination of a thread
    :param f:
    :type f:
    :return:
    :rtype:
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            f(*args, **kwargs)
        except Exception as e:
            arg_string = ', '.join(chain((f'{v}' for v in args),
                                         (f'{k}={v}' for k, v in kwargs.items())))
            log.error(f'{f.__name__}({arg_string}) failed: {e}')
            raise

    return wrapper


@dataclass(init=False)
class CallControlBot(TeamsBot):
    _token_manager: TokenManager

    def __init__(self,
                 *,
                 teams_bot_name,
                 teams_bot_token=None,
                 teams_bot_email=None,
                 teams_bot_url=None,
                 client_id: str = None,
                 client_secret: str = None,
                 debug=False, **kwargs):
        super().__init__(teams_bot_name=teams_bot_name,
                         teams_bot_token=teams_bot_token,
                         teams_bot_email=teams_bot_email,
                         teams_bot_url=teams_bot_url,
                         approved_users=['jkrohn@cisco.com',
                                         'cbarr@tmedemo.com',
                                         'shewitt@tmedemo.com',
                                         'jeokrohn+duharris@gmail.com'],
                         debug=debug, **kwargs)
        # our commands
        self.add_command('/auth', 'authenticate user', self.auth_callback)
        self.add_command('/monitor', 'turn call event monitoring on or off', self.monitor_callback)
        self.add_command('/dial', 'dial a number', self.dial_callback)
        self.add_command('/answer', 'answer alerting call', self.answer_callback)
        self.add_command('/hangup', 'hang up alerting call', self.hangup_callback)

        self._integration = Integration(client_id=client_id, client_secret=client_secret)
        redis_host = os.getenv('REDIS_HOST')
        redis_url = os.getenv('REDIS_TLS_URL') or os.getenv('REDIS_URL')
        if redis_host or redis_url:
            self._token_manager = RedisTokenManager(bot_token=teams_bot_token, integration=self._integration,
                                                    redis_host=redis_host,
                                                    redis_url=redis_url)
            self.add_command('/redis', 'redis commands: /redis info|clear', self.redis_callback)
        else:
            self._token_manager = YAMLTokenManager(bot_token=teams_bot_token, integration=self._integration,
                                                   yml_base='wxc_cc_bot')
        self._token_manager.register_redirect(flask=self)
        self._thread_pool = ThreadPoolExecutor()

        # add a view function for call events
        self.add_url_rule('/callevent/<user_id>', endpoint='callevent', view_func=self.call_event, methods=('POST',))

    def call_event_url(self, user_id: str) -> str:
        """
        User specific call event URL
        :param user_id:
        :return:
        """
        return f'{self.teams_bot_url}/callevent/{user_id}'

    def call_event(self, user_id: str):
        """
        view function for posts to callevents endpoint
        :param user_id:
        :return:
        """

        @catch_exception
        def thread_handle(user_id: str, json_data: str):
            """
            Actually handle a call event, runs in separate thread
            :param user_id:
            :param json_data:
            :return:
            """
            if not self._token_manager.get_user_context(user_id=user_id):
                return
            event = TelephonyEvent.parse_obj(json_data)
            call = event.data
            # simply post a message with the call info
            self.teams.messages.create(toPersonId=user_id, markdown="Call Event:\n```\n" +
                                                                    json.dumps(json.loads(call.json()),
                                                                               indent=2) + "\n```")

        # actually handle in dedicated thread to avoid lock-up
        self._thread_pool.submit(thread_handle, user_id=user_id, json_data=flask.request.json)
        return ''

    def auth_callback(self, message: Message):
        """
        handler for /auth command
        :param message:
        :return:
        """

        @catch_exception
        def authenticate(user_id: str, user_email: str):
            """
            Authenticate sender of /auth command
            :return:
            """
            user_context = self._token_manager.get_user_context(user_id=user_id)
            if len(line) == 2 and line[1] == 'clear':
                if not user_context:
                    self.teams.messages.create(toPersonId=user_id,
                                               text=f'No user context for {user_email}')
                    return
                self._token_manager.set_user_context(user_id=user_id)
                self.teams.messages.create(toPersonId=user_id,
                                           text=f'Cleared user context for {user_email}')
                return

            if user_context:
                self.teams.messages.create(toPersonId=user_id,
                                           text=f'User context for {user_email}: access token valid until '
                                                f'{user_context.tokens.expires_at}')
                return
            self.teams.messages.create(toPersonId=user_id, text=f'No user context for {user_email}')

            # register auth flow and get flow id
            flow_id = self._token_manager.start_flow(user_id=user_id)

            # get auth URL and share URL with user
            auth_url = self._integration.auth_url(state=flow_id)
            self.teams.messages.create(toPersonEmail=user_email,
                                       markdown=f'Click this [link]({auth_url}) to authenticate ({flow_id})')
            return

        line = list(map(lambda x: x.lower(), message.text.split()))
        if len(line) > 2 or len(line) == 2 and line[1] != 'clear':
            return 'usage: /auth [clear]'
        user_email = message.personEmail
        user_id = message.personId
        self._thread_pool.submit(authenticate, user_id=user_id, user_email=user_email)
        return ''

    def monitor_callback(self, message: Message):
        """
        /monitor commamd
        :param message:
        :return:
        """
        line = message.text.split()
        if len(line) != 2 or line[1].lower() not in ['on', 'off']:
            return 'usage: /monitor on|off'
        user_context = self._token_manager.get_user_context(user_id=message.personId)
        if user_context is None or not user_context.tokens.access_token:
            return f'User {message.personEmail} not authenticated. Use /auth command first'
        with WebexSimpleApi(tokens=user_context.tokens) as api:
            # delete all existing webhooks for this user
            webhooks = api.webhook.list()
            webhooks = [wh for wh in webhooks
                        if wh.app_id_uuid == self._integration.client_id and
                        wh.resource == WebHookResource.telephony_calls and
                        wh.target_url.endswith(message.personId)]
            if webhooks:
                # delete all of them
                list(self._thread_pool.map(lambda wh: api.webhook.webhook_delete(webhook_id=wh.webhook_id),
                                           webhooks))

            if line[1] == 'on':
                # turn monitoring on
                # create webhook for telephony event for the current user
                api.webhook.create(name=str(uuid.uuid4()),
                                   target_url=self.call_event_url(user_id=message.personId),
                                   resource='telephony_calls',
                                   event='all')
        return ''

    def dial_callback(self, message: Message):
        """
        /dial command
        :param message:
        :return:
        """
        line = message.text.split()
        if len(line) != 2:
            return 'Usage: /dial <dial string>'
        user_context = self._token_manager.get_user_context(user_id=message.personId)
        if user_context is None or not user_context.tokens.access_token:
            return f'User {message.personEmail} not authenticated. Use /auth command first'
        with WebexSimpleApi(tokens=user_context.tokens) as api:
            number = line[1]
            api.telephony.dial(destination=number)

        return f'Calling {number}...'

    def answer_callback(self, message: Message):
        """
        /answer command
        :param message:
        :return:
        """
        line = message.text.split()
        if len(line) != 1:
            return 'Usage: /answer'
        user_context = self._token_manager.get_user_context(user_id=message.personId)
        if user_context is None or not user_context.tokens.access_token:
            return f'User {message.personEmail} not authenticated. Use /auth command first'

        @catch_exception
        def answer_call(user_id: str):
            user_context = self._token_manager.get_user_context(user_id=message.personId)
            with WebexSimpleApi(tokens=user_context.tokens) as api:
                # list calls
                calls = api.telephony.list_calls()
                # find call in 'alerting'
                alerting_call = next((c for c in calls if c.state == 'alerting'), None)
                if alerting_call is None:
                    self._thread_pool.submit(self.teams.messages.create, toPersonId=user_id,
                                             text='No call in "alerting"')
                    return
                # answer that call
                self._thread_pool.submit(self.teams.messages.create,
                                         toPersonId=user_id,
                                         text=f'answering call from {alerting_call.remote_party.name}'
                                              f'({alerting_call.remote_party.number})')
                self._thread_pool.submit(catch_exception(api.telephony.answer), call_id=alerting_call.call_id)
            return

        # answer_call(user_id=message.personId)
        # submit thread to actually answer the call
        self._thread_pool.submit(answer_call, user_id=message.personId)
        return ''

    def hangup_callback(self, message: Message):
        """
        /hangup command
        :param message:
        :return:
        """
        line = message.text.split()
        if len(line) != 1:
            return 'Usage: /hangup'
        user_context = self._token_manager.get_user_context(user_id=message.personId)
        if user_context is None or not user_context.tokens.access_token:
            return f'User {message.personEmail} not authenticated. Use /auth command first'

        @catch_exception
        def hangup_call(user_id: str):
            user_context = self._token_manager.get_user_context(user_id=message.personId)
            with WebexSimpleApi(tokens=user_context.tokens) as api:
                # list calls
                calls = api.telephony.list_calls()
                # find call in 'connected'
                connected_call = next((c for c in calls if c.state == 'connected'), None)
                if connected_call is None:
                    self._thread_pool.submit(self.teams.messages.create, toPersonId=user_id,
                                             text='No connected call')
                    return
                # hang up that call
                self._thread_pool.submit(self.teams.messages.create,
                                         toPersonId=user_id,
                                         text=f'hanging up call from {connected_call.remote_party.name}'
                                              f'({connected_call.remote_party.number})')
                self._thread_pool.submit(catch_exception(api.telephony.hangup), call_id=connected_call.call_id)
            return

        # submit thread to actually hang up the call
        self._thread_pool.submit(hangup_call, user_id=message.personId)
        return ''

    def redis_callback(self, message: Message):
        """
        /redis command
        :param message:
        :return:
        """

        def usage():
            self.teams.messages.create(toPersonId=message.personId,
                                       text=f'usage: /redis info|clear')

        line: List[str] = message.text.split()
        if len(line) != 2:
            usage()
            return
        cmd = line[1].lower()
        if cmd not in ['info', 'clear']:
            usage()
            return

        @catch_exception
        def process():
            """
            Actually process the command in separate thread
            :return:
            """
            # noinspection PyTypeChecker
            tm: RedisTokenManager = self._token_manager
            redis = tm.redis

            output = StringIO()
            print(f'/redis {cmd}', file=output)
            print('```', file=output)
            if cmd == 'info':
                # entries in flow set
                # flow information for all flows
                print('---flows---', file=output)
                flow_members = redis.smembers(tm.FLOW_SET)
                for flow_key in flow_members:
                    flow_key = flow_key.decode()
                    flow_info = redis.get(flow_key)
                    try:
                        flow_info = json.dumps(json.loads(flow_info), indent=2)
                    except (json.JSONDecodeError, TypeError):
                        flow_info = str(flow_info)
                    print(f'flow: {flow_key}', file=output)
                    print('\n'.join(f'  {fi_line}' for fi_line in flow_info.splitlines()), file=output)

                # entries in user set
                # user information for all users
                print('--user info---', file=output)
                user_members = redis.smembers(tm.USER_SET)
                for user_key in user_members:
                    user_key = user_key.decode()
                    user_info = redis.get(user_key)
                    try:
                        user_info = json.dumps(json.loads(user_info), indent=2)
                    except (json.JSONDecodeError, TypeError):
                        user_info = str(user_info)
                    print(f'user info: {user_key}', file=output)
                    print('\n'.join(f'  {fi_line}' for fi_line in user_info.splitlines()), file=output)

            elif cmd == 'clear':
                # delete
                # * all active flows
                # * all existing user contexts
                # * flow set
                # * user set
                for redis_key in chain(tm.redis.smembers(tm.FLOW_SET),
                                       tm.redis.smembers(tm.USER_SET),
                                       (tm.FLOW_SET, tm.USER_SET)):
                    tm.redis.delete(redis_key)

            def messages(text: str):
                """
                Split long message in parts to avoit posting too long messages
                :param text:
                :return:
                """
                part = ''
                for text_line in text.splitlines():
                    part = '\n'.join((part, text_line))
                    if len(part) > 1500:
                        part = part + '\n```'
                        yield part
                        part = '```'
                if len(part) > 3:
                    yield part + '\n```'

            for sub_msg in messages(output.getvalue()):
                self.teams.messages.create(toPersonId=message.personId,
                                           markdown=sub_msg)

        # actually process the command in a separate thread
        self._thread_pool.submit(process)
        return ''


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(process)d] %(threadName)s %(levelname)s %(name)s %('
                                                'message)s')
logging.getLogger('urllib3.connectionpool').setLevel(logging.INFO)
logging.getLogger('webexteamssdk.restsession').setLevel(logging.WARNING)

# determine public URL for Bot

heroku_name = os.getenv('HEROKU_NAME')
if heroku_name is None:
    log.debug('not running on Heroku. Using ngrok to obtain a public URL')
    bot_url = ngrokhelper.get_public_url(local_port=LOCAL_BOT_PORT)
else:
    log.debug(f'running on heroku as {heroku_name}')
    bot_url = f'https://{heroku_name}.herokuapp.com'
log.debug(f'Webhook URL: {bot_url}')

# Create a new bot
bot_email = os.getenv('WXC_CC_BOT_EMAIL')
teams_token = os.getenv('WXC_CC_BOT_ACCESS_TOKEN')
bot_app_name = os.getenv('WXC_CC_BOT_NAME')
client_id = os.getenv('WXC_CC_INTEGRATION_CLIENT_ID')
client_secret = os.getenv('WXC_CC_INTEGRATION_CLIENT_SECRET')

bot = CallControlBot(teams_bot_name=bot_app_name, teams_bot_token=teams_token,
                     teams_bot_url=bot_url, teams_bot_email=bot_email, debug=True,
                     client_id=client_id, client_secret=client_secret)

if __name__ == '__main__':
    # Run Bot
    bot.run(host='0.0.0.0', port=LOCAL_BOT_PORT)
