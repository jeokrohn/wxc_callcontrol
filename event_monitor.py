#!/usr/bin/env python3
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
from itertools import chain
from typing import Optional, Dict, Union, Type

import flask
import requests
import yaml
from dotenv import load_dotenv
from pydantic import BaseModel
from webexteamsbot import TeamsBot
from webexteamssdk import Message, WebexTeamsAPI, Person

import ngrokhelper
from tokens import Tokens
from wx_simple_api import WebexSimpleApi, TelephonyEvent, WebHookResource

log = logging.getLogger(__name__)

load_dotenv()

LOCAL_BOT_PORT = 6001


@dataclass(init=False)
class ConfigBackend(ABC):
    config_id: str

    def __init__(self, *, config_id: str = None):
        self.config_id = config_id or self.__class__.__name__

    @abstractmethod
    def get(self) -> dict:
        ...

    @abstractmethod
    def put(self, data: dict):
        ...


TypeConfigBackend = Type[ConfigBackend]


class ConfigBackendFactory:
    def __init__(self, *, backend: TypeConfigBackend):
        self._backend = backend

    def get_backend(self, *, config_id: str = None):
        return self._backend(config_id=config_id)


class ConfigYML(ConfigBackend):
    @property
    def yml_path(self) -> str:
        path = os.path.join(os.getcwd(), f'{self.config_id}.yml')
        return path

    def get(self) -> dict:
        # read data from YML
        try:
            with open(self.yml_path, mode='r') as file:
                data = yaml.safe_load(file)
        except FileNotFoundError:
            data = {}
        return data

    def put(self, data: dict):
        # write data to file
        with open(self.yml_path, mode='w') as file:
            yaml.dump(data, file)


@dataclass
class Integration:
    client_id: str
    client_secret: str
    # TODO: find out which scopes are actually required
    scopes = 'spark:calls_write spark:all spark:kms spark:calls_read spark-admin:telephony_config_read ' \
             'spark-admin:telephony_config_write spark-admin:people_read'
    # scopes = 'spark:people_read spark:calls_write spark:kms spark:calls_read spark-admin:telephony_config_read'
    redirect_url = 'http://localhost:6001/redirect'
    auth_service = 'https://webexapis.com/v1/authorize'
    token_service = 'https://webexapis.com/v1/access_token'

    def auth_url(self, *, state: str) -> str:
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_url,
            'scope': self.scopes,
            'state': state
        }
        full_url = f'{self.auth_service}?{urllib.parse.urlencode(params)}'
        return full_url

    def tokens_from_code(self, code: str) -> Tokens:
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
        remaining = tokens.remaining
        if remaining < 600:
            log.debug(f'Getting new access token, valid until {tokens.expires_at}, remaining {remaining}')
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


class RedirectHandler:
    """
    Helper class to process GETs on redirect URI for OAuth flows
    """

    def __init__(self):
        # flow registry has a slot for each active flow
        # while we are still waiting for the flow to complete the slot holds the Event to signal flow completion
        # on seeing the POST to th redirect endpoint the code is stored in the slot instead
        self._flow_registry: Dict[str, Union[threading.Event, str]] = dict()
        self._flow_registry_lock = threading.Lock()

    def register_flask(self, app: flask.Flask):
        """
        Register redirect endpoint for final step of OAuth flows
        :param app:
        :return:
        """
        # register /redirect endpoint
        app.add_url_rule(rule='/redirect', endpoint='redirect', view_func=self.redirect, methods=('GET',))

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
        # is this a registered flow?
        with self._flow_registry_lock:
            flow_info = self._flow_registry.get(flow_id)
            if flow_info is None:
                log.warning(f'Got redirect for unknown flow id: {flow_id}')
                return 'Unknown flow...'
            flow_info: threading.Event
            # set code as result for this flow and mark as done .. someone is waiting for the event
            self._flow_registry[flow_id] = code
            flow_info.set()
        return 'Authenticated'

    def register_flow(self) -> str:
        """
        Register a new OAuth flow and get a flow id for the new flow
        :return:
        """
        # get UUID for a new redirect flow
        flow_id = str(uuid.uuid4())

        # add an Event to the registry we can wait for until the auth flow completes
        with self._flow_registry_lock:
            self._flow_registry[flow_id] = threading.Event()
        log.debug(f'registered new auth flow: {flow_id}')
        return flow_id

    def get_code_for_flow(self, flow_id: str, timeout: int = 120) -> Optional[str]:
        """
        Return code posted to redirect endpoint for given flow id
        Waits timeout seconds for the flow to terminate, else returns None
        :param flow_id:
        :param timeout
        :return:
        """
        event = self._flow_registry.get(flow_id)
        if event is None:
            log.warning(f'Unknown flow_id: {flow_id}')
            return None
        event: threading.Event
        # wait for event to be set; the event gets set in the /redirect view function
        flow_done = event.wait(timeout=timeout)
        if flow_done:
            code = self._flow_registry[flow_id]
        else:
            code = None
        # remove flow from registry
        with self._flow_registry_lock:
            self._flow_registry.pop(flow_id)
        return code


class UserContext(BaseModel):
    user_id: str
    tokens: Tokens


def catch_exception(f):
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


class CallControlBot(TeamsBot):
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
                                         'shewitt@tmedemo.com'],
                         debug=debug, **kwargs)
        # our commands
        self.add_command('/auth', 'authenticate user', self.auth_callback)
        self.add_command('/monitor', 'turn call event monitoring on ot off', self.monitor_callback)
        self.add_command('/dial', 'dial a number', self.dial_callback)
        self.add_command('/answer', 'answer alerting call', self.answer_callback)
        self.add_command('/hangup', 'hang up alerting call', self.hangup_callback)

        self._config_backend = ConfigYML(config_id='event_monitor')
        self._user_context_registry: Dict[str, UserContext] = dict()
        self.get_user_contexts()

        self._redirect_handler = RedirectHandler()
        self._redirect_handler.register_flask(app=self)
        self._integration = Integration(client_id=client_id, client_secret=client_secret)
        self._call_event_exec = ThreadPoolExecutor()

        # add a view function for call events
        self.add_url_rule('/callevent/<user_id>', endpoint='callevent', view_func=self.call_event, methods=('POST',))

    def get_user_contexts(self):
        config = self._config_backend.get()
        self._user_context_registry = {k: UserContext.parse_obj(v)
                                       for k, v in config.items()}

    def put_user_contexts(self):
        data = {k: json.loads(v.json()) for k, v in self._user_context_registry.items()}
        self._config_backend.put(data)

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

        def thread_handle(user_id: str, json_data: str):
            """
            Actually handle a call event, runs in separate thread
            :param user_id:
            :param json_data:
            :return:
            """
            event = TelephonyEvent.parse_obj(json_data)
            call = event.data
            # simply post a message with the call info
            self.teams.messages.create(toPersonId=user_id, markdown="Call Event:\n```\n" +
                                                                    json.dumps(json.loads(call.json()),
                                                                               indent=2)) + "\n```"

        # actually handle in dedicated thread to avoid lock-up
        if self.get_user_context(user_id=user_id):
            # only handle if we have a user context for that user_id; else ignore
            self._call_event_exec.submit(thread_handle, user_id=user_id, json_data=flask.request.json)
        return ''

    def get_user_context(self, *, user_id: str) -> Optional[UserContext]:
        return self._user_context_registry.get(user_id)

    def set_user_context(self, *, user_context: UserContext):
        self._user_context_registry[user_context.user_id] = user_context
        self.put_user_contexts()

    def auth_callback(self, message: Message):
        """
        handler for /auth command
        :param message:
        :return:
        """

        def authenticate():
            """
            Authenticate sender of /auth command
            :return:
            """
            # register auth flow and get flow id
            flow_id = self._redirect_handler.register_flow()

            # get auth URL and share URL with user
            auth_url = self._integration.auth_url(state=flow_id)
            self.teams.messages.create(toPersonEmail=user_email,
                                       markdown=f'Click this [link]({auth_url}) to authenticate ({flow_id})')

            # get code at end of redirect flow
            code = self._redirect_handler.get_code_for_flow(flow_id=flow_id)
            if code is None:
                self.teams.messages.create(toPersonEmail=user_email,
                                           text=f'Failed to get code ({flow_id})')
                return

            # get tokens from code
            tokens = self._integration.tokens_from_code(code=code)
            tokens.set_expiration()

            # verify that the token actually is for the user who initiated the authentication
            api = WebexTeamsAPI(access_token=tokens.access_token)
            user = api.people.me()
            user: Person
            if user_email != user.emails[0]:
                self.teams.messages.create(toPersonEmail=user_email,
                                           text=f'Got authentication for {user.emails[0]}, expected: {user_email}')
                return
            user_context = UserContext(user_id=user_id,
                                       tokens=tokens)
            self.set_user_context(user_context=user_context)
            self.teams.messages.create(toPersonEmail=user_email,
                                       text=f'Successfully authenticated {user_email}, token valid until '
                                            f'{tokens.expires_at} ({flow_id})')
            return

        # check if we still have valid tokens for user
        # initiate auth flow if needed
        #   * return auth message to user
        # run thread waiting for oauth flow completion
        #   * thread waits for code and adds tokens to cache
        user_email = message.personEmail
        user_id = message.personId
        user_context = self.get_user_context(user_id=user_id)
        if not user_context:
            threading.Thread(target=authenticate).start()
            return f'No user context for {user_email}'
        return f'User context for {user_email}: access token valid until {user_context.tokens.expires_at}'

    def monitor_callback(self, message: Message):
        """
        /monitor commamd
        :param message:
        :return:
        """
        line = message.text.split()
        if len(line) != 2 or line[1].lower() not in ['on', 'off']:
            return 'usage: /monitor on|off'
        user_context = self.get_user_context(user_id=message.personId)
        if user_context is None:
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
                list(self._call_event_exec.map(lambda wh: api.webhook.webhook_delete(webhook_id=wh.webhook_id),
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
        user_context = self.get_user_context(user_id=message.personId)
        if user_context is None:
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
        user_context = self.get_user_context(user_id=message.personId)
        if user_context is None:
            return f'User {message.personEmail} not authenticated. Use /auth command first'

        @catch_exception
        def answer_call(user_id: str):
            user_context = self.get_user_context(user_id=user_id)
            with WebexSimpleApi(tokens=user_context.tokens) as api:
                # list calls
                calls = api.telephony.list_calls()
                # find call in 'alerting'
                alerting_call = next((c for c in calls if c.state == 'alerting'), None)
                if alerting_call is None:
                    self._call_event_exec.submit(self.teams.messages.create, toPersonId=user_id,
                                                 text='No call in "alerting"')
                    return
                # answer that call
                self._call_event_exec.submit(self.teams.messages.create,
                                             toPersonId=user_id,
                                             text=f'answering call from {alerting_call.remote_party.name}'
                                                  f'({alerting_call.remote_party.number})')
                self._call_event_exec.submit(api.telephony.answer, call_id=alerting_call.call_id)
            return

        # answer_call(user_id=message.personId)
        # submit thread to actually answer the call
        self._call_event_exec.submit(answer_call, user_id=message.personId)
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
        user_context = self.get_user_context(user_id=message.personId)
        if user_context is None:
            return f'User {message.personEmail} not authenticated. Use /auth command first'

        @catch_exception
        def hangup_call(user_id: str):
            user_context = self.get_user_context(user_id=user_id)
            with WebexSimpleApi(tokens=user_context.tokens) as api:
                # list calls
                calls = api.telephony.list_calls()
                # find call in 'connected'
                connected_call = next((c for c in calls if c.state == 'connected'), None)
                if connected_call is None:
                    self._call_event_exec.submit(self.teams.messages.create, toPersonId=user_id,
                                                 text='No connected call')
                    return
                # hang up that call
                self._call_event_exec.submit(self.teams.messages.create,
                                             toPersonId=user_id,
                                             text=f'hanging up call from {connected_call.remote_party.name}'
                                                  f'({connected_call.remote_party.number})')
                self._call_event_exec.submit(api.telephony.hangup, call_id=connected_call.call_id)
            return

        # submit thread to actually hang up the call
        self._call_event_exec.submit(hangup_call, user_id=message.personId)
        return ''


# determine public URL for Bot
bot_url = ngrokhelper.get_public_url(local_port=LOCAL_BOT_PORT)

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
