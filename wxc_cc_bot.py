#!/usr/bin/env python3
"""
A simple bot demonstrating some of the capabilities of the Webex Calling call control APIs

The "magic" happens in :class:`CallControlBot`

---------------------
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
from wxc_sdk import WebexSimpleApi
from wxc_sdk.integration import Integration
from wxc_sdk.telephony.calls import TelephonyEvent
from wxc_sdk.webhook import WebHookResource, WebHookEvent
from wxc_sdk.telephony.calls import CallState

import ngrokhelper
from user_context import TokenManager, RedisTokenManager, YAMLTokenManager

log = logging.getLogger(__name__)

load_dotenv()

# local port the Flask server for webhook notifications is running on
LOCAL_BOT_PORT = 6001


def catch_exception(f):
    """
    Decorator to catch and log exceptions which led to termination of a thread

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
                 teams_bot_name: str,
                 teams_bot_token: str,
                 teams_bot_email: str ,
                 teams_bot_url: str,
                 client_id: str,
                 client_secret: str,
                 client_scopes: str,
                 client_redirect_url: str,
                 debug=False):
        """
        :param teams_bot_name: Friendly name for the Bot (webhook name). Bot parameters are obtained from
            https://developer.webex.com/my-apps/wxcc-bot when creating the bot
        :param teams_bot_token: Teams Auth Token for Bot Account
        :param teams_bot_email: Teams Bot Email Address
        :param teams_bot_url: WebHook URL for this Bot

        The teams_bot_* parameters are used to initialize the :class:`webexteamsbot.TeamsBot` base class.

        :param client_id: client ID of the integration the Bot uses to obtain tokens to act on behalf of a user.
            Integration parameters are obtained from https://developer.webex.com/my-apps/wxcc-bot when creating the
            integration.
        :param client_secret: client secret of the integration the Bot uses to obtain tokens to act on behalf of a user
        :param client_scopes: scopes of the integration the Bot uses to obtain tokens to act on behalf of a user
        :param client_redirect_url: redirect URL of the integration the Bot uses to obtain tokens to act on
            behalf of a user
        :param debug: debug mode

        During initalization some bot commands are registered using the :meth:`webexteamsbot.add_command` method.

        ========    =============================   ===========
        Command     Handler                         Description
        ========    =============================   ===========
        /auth       :meth:`auth_callback`           Authenticate current user if needed or print authentication state.
        /monitor    :meth:`monitor_callback`        Enable or disable monitoring von ``telephony_call`` events for curent
                                                    user. Events are echoed to the chat.
        /dial       :meth:`dial_callback`           Dial a destination for the current user. Uses
                                                    :meth:`wxc_sdk.telephony.calls.CallsApi.dial`
        /answer     :meth:`answer_callback`         Answer an incoming call for the current user. Uses
                                                    :meth:`wxc_sdk.telephony.calls.CallsApi.list_calls` and
                                                    :meth:`wxc_sdk.telephony.calls.CallsApi.answer`
        /hangup     :meth:`hangup_callback`         Hang up an active call. Uses
                                                    :meth:`wxc_sdk.telephony.calls.CallsApi.hangup`
        /history    :meth:`call_history_callback`   Show call history for current user. Uses
                                                    :meth:`wxc_sdk.telephony.calls.CallsApi.call_history`
        /redis      :meth:`redis_callback`          Interact with Redis data store. This command is only available if the
                                                    Bot is using the Redis integration via
                                                    a :class:`user_context.RedisTokenManager` token manager.
        ========    =============================   ===========

        The bot needs to persist state (access and refresh tokens) for each user so that users don't need to
        reauthenticate every time the bot has been restarted. This per user state is stored in
        :class:`user_context.UserContext` objects which are managed by a :class:`user_context.TokenManager`. During
        initialization the bot creates either a :class:`user_context.YAMLTokenManager` (persist state in local yaml
        file) or a
        :class:`user_context.RedisTokenManager` (persist user state in Redis) for token management and handling of
        OAuth authentication flows. A
        :class:`user_context.RedisTokenManager` is only used if the bot is running in an environment with a running
        Redis server. This is determined by checking the ``REDIS_HOST``, ``REDIS_TLS_URL``, and ``REDIS_URL``
        environment variables.

        The ``/redirect`` endpoint under the bot base url (for example http://localhost:6001/redirect) is
        registered
        with the :class:`flask.Flask` base class of :class:`CallControlBot`. This endpoint is used as redirect URL
        for the OAuth authorization flows to obtain access tokens for the bot users.
        """
        # set up base class: :class:`webexteamsbot.TeamsBot`
        super().__init__(teams_bot_name=teams_bot_name,
                         teams_bot_token=teams_bot_token,
                         teams_bot_email=teams_bot_email,
                         teams_bot_url=teams_bot_url,
                         debug=debug)
        # our commands
        self.add_command('/auth', 'authenticate user: /auth [clear|force|maintenance]', self.auth_callback)
        self.add_command('/monitor', 'turn call event monitoring on or off', self.monitor_callback)
        self.add_command('/dial', 'dial a number', self.dial_callback)
        self.add_command('/answer', 'answer alerting call', self.answer_callback)
        self.add_command('/hangup', 'hang up alerting call', self.hangup_callback)
        self.add_command('/history', 'get call history', self.call_history_callback)

        self._integration = Integration(client_id=client_id, client_secret=client_secret, scopes=client_scopes,
                                        redirect_url=client_redirect_url)
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
        User specific call event URL: ``/callevent/{user_id}``

        :param user_id: user ID to create a ``telephony_call`` webhook events URL for.
        :type user_id: str
        :return: generated URL
        :rtype: str
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
        handler for /auth command.

        The handler supports:
            *   ``/auth``: check if the user has been authenticated. Get authorization URL if needed, else display
                existing access token validity
            *   ``/auth clear``: clear existing user context for current user
            *   ``/auth force``: force new authentication of current user even if the bot already has tokens for the
                current user.
            *   ``/auth maintenance``: force :meth:`user_context.RedisTokenManager.flow_maintenance`. This cleans up
                all dangling OAuth
                authorization flows: flows which have been initiated but never completed.

                This command only makes sense if the bot is using a :class:`user_context.RedisTokenManager`.

        :param message: The message from the user in the 1:1 space with the bot
        :type message: :class:`webexteamssdk.Message`
        :return: response to user
        :rtype: str
        """

        @catch_exception
        def authenticate(user_id: str, user_email: str):
            """
            Actually handle /auth command in a thread to avoid lockup of the
            web server
            handling the Webhook messagee.

            :param user_id: user id
            :type user_id: str
            :param user_email: user email
            :type user_email: str
            """
            # get user context from token manager
            user_context = self._token_manager.get_user_context(user_id=user_id)

            if len(line) == 2 and line[1] == 'clear':
                # /auth clear: clear existing user context
                if not user_context:
                    self.teams.messages.create(toPersonId=user_id,
                                               text=f'No user context for {user_email}')
                    return
                self._token_manager.set_user_context(user_id=user_id)
                self.teams.messages.create(toPersonId=user_id,
                                           text=f'Cleared user context for {user_email}')
                return

            if len(line) == 2 and line[1] == 'maintenance':
                # /auth maintenance: force authorization flow maintenance
                # auth flow maintenance
                if not isinstance(self._token_manager, RedisTokenManager):
                    self.teams.messages.create(toPersonId=user_id,
                                               text='/auth maintenance only makes sense when using Redis backend')
                    return
                tm: RedisTokenManager = self._token_manager
                # catch output of flow maintenance in string
                output = StringIO()
                tm.flow_maintenance(force=True, output=output)

                # message to user with result of flow maintenance
                self.teams.messages.create(toPersonId=user_id,
                                           text=output.getvalue())
                return

            force_auth = len(line) == 2 and line[1] == 'force'
            if user_context:
                # echo existing user context (token validity) back to user
                self.teams.messages.create(toPersonId=user_id,
                                           text=f'User context for {user_email}: access token valid until '
                                                f'{user_context.tokens.expires_at}')
                if not force_auth:
                    # done if the user doesn't want to force new authentication
                    return
            else:
                # we don't have a user context
                self.teams.messages.create(toPersonId=user_id, text=f'No user context for {user_email}')

            # to initiate authentication we need a new flow id, then have to create an authorization URL, and finally
            # share the authorization URL with the user so that the user can initiate the authorization flow using
            # that link

            # register auth flow and get flow id
            flow_id = self._token_manager.start_flow(user_id=user_id)

            # get auth URL and share URL with user
            auth_url = self._integration.auth_url(state=flow_id)
            self.teams.messages.create(toPersonEmail=user_email,
                                       markdown=f'Click this [link]({auth_url}) to authenticate ({flow_id})')
            return

        def usage():
            """
            send usage message for /auth command to current user
            """
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
        else:
            # handle actual authentication in thread to prevent delaying the response to the POST on the Webhook URL
            self._thread_pool.submit(authenticate, user_id=user_id, user_email=user_email)
        return ''

    def monitor_callback(self, message: Message):
        """
        handler for /monitor command

        The handler supports:
            * /montor on: turn ``telephony_calls`` event monitoring on
            * /montor off: turn ``telephony_calls`` event monitoring off

        :param message: The message from the user in the 1:1 space with the bot
        :type message: :class:`webexteamssdk.Message`
        :return: response to user
        :rtype: str

        To turn monitoring on a webhook for ``telephony_calls`` events is created for the current user. The URL for
        the webhook (destination for the POST from Webex) is user specific and created using :meth:`call_event_url`.
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
                                   resource=WebHookResource.telephony_calls,
                                   event=WebHookEvent.all)
                return 'Monitor on: listening for telephony_calls events'
        return 'Monitoring off'

    def dial_callback(self, message: Message):
        """
        handler for /dial command

        :param message: The message from the user in the 1:1 space with the bot
        :type message: :class:`webexteamssdk.Message`
        :return: response to user
        :rtype: str
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
        handler for /answer command

        :param message: The message from the user in the 1:1 space with the bot
        :type message: :class:`webexteamssdk.Message`
        :return: response to user
        :rtype: str
        """
        line = message.text.split()
        if len(line) != 1:
            return 'Usage: /answer'
        user_context = self._token_manager.get_user_context(user_id=message.personId)
        if user_context is None or not user_context.tokens.access_token:
            return f'User {message.personEmail} not authenticated. Use /auth command first'

        @catch_exception
        def answer_call(user_id: str):
            """
            Actually handle /answer call in thread context to prevent blocking
            :param user_id:
            """
            user_context = self._token_manager.get_user_context(user_id=message.personId)
            with WebexSimpleApi(tokens=user_context.tokens) as api:
                # list calls
                calls = list(api.telephony.calls.list_calls())
                # find call in 'alerting'
                alerting_call = next((c for c in calls if c.state == CallState.alerting), None)
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

        # submit thread to actually answer the call
        # answer_call(user_id=message.personId)
        self._thread_pool.submit(answer_call, user_id=message.personId)
        return ''

    def hangup_callback(self, message: Message):
        """
        handler for /hangup command

        :param message: The message from the user in the 1:1 space with the bot
        :type message: :class:`webexteamssdk.Message`
        :return: response to user
        :rtype: str
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
        handler for /redis command

        :param message: The message from the user in the 1:1 space with the bot
        :type message: :class:`webexteamssdk.Message`
        :return: response to user
        :rtype: str
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

    def call_history_callback(self, message: Message)->str:
        """
        handler for /history command

        :param message: The message from the user in the 1:1 space with the bot
        :type message: :class:`webexteamssdk.Message`
        :return: response to user
        :rtype: str
        """
        user_context = self._token_manager.get_user_context(user_id=message.personId)
        if user_context is None or not user_context.tokens.access_token:
            return f'User {message.personEmail} not authenticated. Use /auth command first'

        @catch_exception
        def process():
            """
            Actually process the command in separate thread
            :return:
            """
            with WebexSimpleApi(tokens=user_context.tokens) as api:
                history = list(api.telephony.calls.call_history())
            history.sort(key=lambda h: h.time)
            text = '\n'.join(f'{h.time}, {h.call_type.name:10} - {h.number} ({h.name})' for h in history)
            self.teams.messages.create(toPersonId=message.personId,
                                       text=text)

        self._thread_pool.submit(process)
        return ''


# set up logging for the bot
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(process)d] %(threadName)s %(levelname)s %(name)s %('
                                                'message)s')
logging.getLogger('urllib3.connectionpool').setLevel(logging.INFO)
logging.getLogger('webexteamssdk.restsession').setLevel(logging.WARNING)

# to disable logging of WXC SDK REST messages change the log level
logging.getLogger('wxc_sdk.rest').setLevel(logging.DEBUG)


def create_app() -> CallControlBot:
    """
    Create a :class:`CallControlBot` instance.

    :return: the bot instance; subclass of :class:`flask.Flask`
    :rtype: CallControlBot

    All parameters to create the bot are read from environment variables:

    ================================    ===========
    Environment variable                Description
    ================================    ===========
    WXC_CC_BOT_EMAIL                    bot email
    WXC_CC_BOT_ACCESS_TOKEN             bot access token
    WXC_CC_BOT_NAME                     bot name
    WXC_CC_INTEGRATION_CLIENT_ID        client id  for integration that is used to obtain tokens to act on behalf
                                        of the user that is interacting with the bot.
    WXC_CC_INTEGRATION_CLIENT_SECRET    client secret  for integration that is used to obtain tokens to act on behalf
                                        of the user that is interacting with the bot.
    WXC_CC_INTEGRATION_CLIENT_SCOPES    scopes for integration that is used to obtain tokens to act on behalf of the
                                        user that is interacting with the bot. Spoce separated list of scopes.
    ================================    ===========

    The scripts reads ``.env`` from the current directory. This file can be used to set all these variables. A
    template (``.env (sample)``) exists in the project directory:

    .. literalinclude:: ../.env (sample)

    :func:`create_app` is used in the ``Procfile`` when deploying to Heroku:

    .. literalinclude:: ../Procfile

    """

    # determine public URL for Bot
    heroku_name = os.getenv('HEROKU_NAME')
    if heroku_name is None:
        log.debug('not running on Heroku. Using ngrok to obtain a public URL')
        bot_url = ngrokhelper.get_public_url(local_port=LOCAL_BOT_PORT)
    else:
        log.debug(f'running on heroku as {heroku_name}')
        bot_url = f'https://{heroku_name}.herokuapp.com'
    log.debug(f'Webhook base URL: {bot_url}')

    # Create a new bot
    bot_email = os.getenv('WXC_CC_BOT_EMAIL')
    teams_token = os.getenv('WXC_CC_BOT_ACCESS_TOKEN')
    bot_app_name = os.getenv('WXC_CC_BOT_NAME')
    client_id = os.getenv('WXC_CC_INTEGRATION_CLIENT_ID')
    client_secret = os.getenv('WXC_CC_INTEGRATION_CLIENT_SECRET')
    client_scopes = os.getenv('WXC_CC_INTEGRATION_CLIENT_SCOPES')
    client_redirect_url = f'{bot_url}/redirect'

    bot = CallControlBot(teams_bot_name=bot_app_name, teams_bot_token=teams_token,
                         teams_bot_url=bot_url, teams_bot_email=bot_email, debug=True,
                         client_id=client_id, client_secret=client_secret, client_scopes=client_scopes,
                         client_redirect_url=client_redirect_url)
    return bot


if __name__ == '__main__':
    # Run Bot
    bot = create_app()
    bot.run(host='0.0.0.0', port=LOCAL_BOT_PORT)
