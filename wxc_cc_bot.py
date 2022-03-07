#!/usr/bin/env python3
"""
A simple bot demonstrating some of the capabilities of the Webex Calling call control APIs
"""
import json
import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import wraps
from io import StringIO
from itertools import chain
from typing import List

from dotenv import load_dotenv
from flask import request as flask_request
from webexteamsbot import TeamsBot
from webexteamssdk import Message

import ngrokhelper
from integration import Integration
from user_context import TokenManager, RedisTokenManager, YAMLTokenManager
from webex_simple_api import WebexSimpleApi
from webex_simple_api.telephony.calls import TelephonyEvent
from webex_simple_api.webhook import WebHookResource

log = logging.getLogger(__name__)

load_dotenv()

LOCAL_BOT_PORT = 6001


def catch_exception(f):
    """
    Wrapper to catch and log exceptions which led to termination of a thread

    :meta private:
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
    """
    The call control demo bot
    """
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
        self.add_command('/auth', 'authenticate user: /auth [clear|force|maintenance]', self.auth_callback)
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
        :type user_id: str
        :return: generated URL
        :meta private:
        """
        return f'{self.teams_bot_url}/callevent/{user_id}'

    def call_event(self, user_id: str):
        """
        view function for posts to callevent endpoint
        Handle webhook messages

        :param user_id: user id, passed as parameter in the request URL
        :type user_id: str
        :return:
        :meta private:
        """

        @catch_exception
        def thread_handle(user_id: str, json_data: str):
            """
            Actually handle a call event, runs in separate thread

            :param user_id:
            :type user_id: str
            :param json_data:
            :type json_data: str
            """
            log.debug(f'webhook event: {json_data}')
            if not self._token_manager.get_user_context(user_id=user_id):
                log.warning(f'webhook event: no user context for user id {user_id}')
                return
            event = TelephonyEvent.parse_obj(json_data)
            call = event.data
            # simply post a message with the call info
            self.teams.messages.create(toPersonId=user_id, markdown="Call Event:\n```\n" +
                                                                    json.dumps(json.loads(call.json()),
                                                                               indent=2) + "\n```")

        # actually handle in dedicated thread to avoid lock-up
        self._thread_pool.submit(thread_handle, user_id=user_id, json_data=flask_request.json)
        return ''

    def auth_callback(self, message: Message) -> str:
        """
        handler for /auth command

        :param message:
        :type message: Message
        :return: response to user
        :meta private:
        """

        @catch_exception
        def authenticate(user_id: str, user_email: str):
            """
            Authenticate sender of /auth command

            :param user_id: user id
            :type user_id: str
            :param user_email: user email
            :type user_email: str
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
            if len(line) == 2 and line[1] == 'maintenance':
                # auth flow maintenance
                if not isinstance(self._token_manager, RedisTokenManager):
                    self.teams.messages.create(toPersonId=user_id,
                                               text='/auth maintenance only makes sense when using Redis backend')
                    return
                tm: RedisTokenManager = self._token_manager
                output = StringIO()
                tm.flow_maintenance(force=True, output=output)
                self.teams.messages.create(toPersonId=user_id,
                                           text=output.getvalue())
                return

            force_auth = len(line) == 2 and line[1] == 'force'
            if user_context:
                self.teams.messages.create(toPersonId=user_id,
                                           text=f'User context for {user_email}: access token valid until '
                                                f'{user_context.tokens.expires_at}')
                if not force_auth:
                    return
            else:
                self.teams.messages.create(toPersonId=user_id, text=f'No user context for {user_email}')

            # register auth flow and get flow id
            flow_id = self._token_manager.start_flow(user_id=user_id)

            # get auth URL and share URL with user
            auth_url = self._integration.auth_url(state=flow_id)
            self.teams.messages.create(toPersonEmail=user_email,
                                       markdown=f'Click this [link]({auth_url}) to authenticate ({flow_id})')
            return

        def usage():
            self.teams.messages.create(toPersonId=user_id,
                                       text="""usage:
* /auth: initiate auth flow if needed
* /auth clear: clear existing user context
* /auth force: force new authentication w/o checking for existing user context
* /auth maintenance: flow maintenance, delete open OAuth flows older than 5 minutes""")
            return

        line = list(map(lambda x: x.lower(), message.text.split()))
        user_email = message.personEmail
        user_id = message.personId

        if len(line) > 2 or len(line) == 2 and line[1] not in ['clear', 'force', 'maintenance']:
            usage()
        self._thread_pool.submit(authenticate, user_id=user_id, user_email=user_email)
        return ''

    def monitor_callback(self, message: Message):
        """
        /monitor commamd

        :param message:
        :type message: Message
        :return: response to user
        :meta private:
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
        :type message: Message
        :return: response to user
        :meta private:
        """
        line = message.text.split()
        if len(line) != 2:
            return 'Usage: /dial <dial string>'
        user_context = self._token_manager.get_user_context(user_id=message.personId)
        if user_context is None or not user_context.tokens.access_token:
            return f'User {message.personEmail} not authenticated. Use /auth command first'
        with WebexSimpleApi(tokens=user_context.tokens) as api:
            number = line[1]
            api.telephony.calls.dial(destination=number)

        return f'Calling {number}...'

    def answer_callback(self, message: Message):
        """
        /answer command

        :param message:
        :type message: Message
        :return: response to user
        :meta private:
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
                calls = api.telephony.calls.list_calls()
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
                self._thread_pool.submit(catch_exception(api.telephony.calls.answer), call_id=alerting_call.call_id)
            return

        # answer_call(user_id=message.personId)
        # submit thread to actually answer the call
        self._thread_pool.submit(answer_call, user_id=message.personId)
        return ''

    def hangup_callback(self, message: Message):
        """
        /hangup command

        :param message:
        :type message: Message
        :return: response to user
        :meta private:
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
                calls = api.telephony.calls.list_calls()
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
                self._thread_pool.submit(catch_exception(api.telephony.calls.hangup), call_id=connected_call.call_id)
            return

        # submit thread to actually hang up the call
        self._thread_pool.submit(hangup_call, user_id=message.personId)
        return ''

    def redis_callback(self, message: Message):
        """
        /redis command

        :param message:
        :type message: Message
        :return: response to user
        :meta private:
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


def create_app() -> CallControlBot:
    """
    Create a bot instance

    :return: the Flask app object
    :rtype: CallControlBot
    """
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
    return bot


if __name__ == '__main__':
    # Run Bot
    bot = create_app()
    bot.run(host='0.0.0.0', port=LOCAL_BOT_PORT)
