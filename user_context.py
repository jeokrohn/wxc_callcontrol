"""
Management of user contexts for the bot.
User contexts are either stored in Redis or in a local file.

* :class:`TokenManager`: abstract base class for token managers
* :class:`YAMLTokenManager`: token manager storing tokens for users in local YAML file
* :class:`RedisTokenManager`: token manager storing tokens and OAuth flow state in  Redis

------------------
"""
import datetime
import json
import logging
import os
import threading
import urllib.parse
import uuid
from abc import ABC, abstractmethod
from io import StringIO, TextIOBase
from typing import Optional

import pydantic
import pytz
import redis
import requests
import yaml
from flask import Flask, request as flask_request
from pydantic import BaseModel, Field
from webexteamssdk import WebexTeamsAPI

from wxc_sdk.integration import Integration
from wxc_sdk.tokens import Tokens
from wxc_sdk import WebexSimpleApi

log = logging.getLogger(__name__)

__all__ = ['UserContext', 'TokenManager', 'YAMLTokenManager', 'RedisTokenManager']

# minimal token lifetime at which we consider refreshing tokens
MIN_TOKEN_LIFETIME_SECONDS = 120


class UserContext(BaseModel):
    """
    User context. For each user we need to keep track of the tokens obtained for that user
    """
    #: user id
    user_id: str
    #: tokens for the user: :class:`wxc_sdk.tokens.Tokens`
    tokens: Tokens


class TokenManager(ABC):
    """
    Token manager consolidates all functions around tokens.
        * registering a new OAuth flow
        * processing the code at the end of the flow to obtain tokens
        * storing user contexts
        * providing access to user contexts
    """

    def __init__(self, bot_token: str, integration: Integration, **kwargs):
        """

        :param bot_token:  bot Token
        :param integration: :class:`wxc_sdk.integration.Integration`
        :param kwargs:
        """
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

        :param user_id: user id to register a flow for
        :type user_id: str
        :return: flow id for the new flow
        :rtype: str
        """
        ...

    @abstractmethod
    def process_redirect(self, *, flow_id: str, code: str) -> str:
        """
        Process redirect at end of OAuth flow. New tokens are stored in user context

        :param flow_id: OAuth flow id
        :type flow_id: str
        :param code: code obtained from final URL in OAuth flow
        :type code: str
        :return: text for HTTP response
        :rtype: str
        """
        ...

    @abstractmethod
    def get_user_context(self, *, user_id: str) -> Optional[UserContext]:
        """
        Get user context for given user_id

        :param user_id: id of user to get context for
        :type user_id: str
        :return: user context
        :rtype: UserContext
        """
        ...

    def set_user_context(self, *, user_id: str, user_context: UserContext = None):
        """
        Add user context to cache or clear it from cache (user_context==None)

        :param user_id: user id
        :type user_id: str
        :param user_context: user context to set; if None then clear user context for this user
        :type user_context: UserContext
        """
        ...

    def register_redirect(self, *, flask: Flask):
        """
        Register /redirect endpoint for OAuth flows.

        :meth:`redirect` is registered as view handler with flask by calling :meth:`flask.Flask.add_url_rule`.
        The view handler is called whenever a request on the /redirect endpoint needs to be handled.

        :param flask: Flask app to register the /redirect endpoint with
        :type flask: :class:`flask.Flask`
        """
        # register /redirect endpoint
        flask.add_url_rule(rule='/redirect', endpoint='redirect', view_func=self.redirect, methods=('GET',))

    def redirect(self):
        """
        view function for GET on /redirect at end of authorization flow.

        Get code and state (flow id) from URL and set event on the registered flow

        The view function is called whenever a request on /redirect needs to be handled. Request details are available
        in the global :attr:`flask.request` variable (imported as ``flask_request``).

        Authorization code and flow id are contained in the query string of the request URL. The parsed arguments
        of the query string can be
        found in the :attr:`flask.Request.args` attribute of ``flask_request``.

        """
        # get code and flow id from URL
        code = flask_request.args.get('code')
        flow_id = flask_request.args.get('state')
        log.debug(f'handle /redirect: code={code}, flow id={flow_id}')

        if not all((code, flow_id)):
            return ''
        return self.process_redirect(flow_id=flow_id, code=code)

    def token_refresh(self, *, tokens: Tokens) -> bool:
        """
        try to refresh the tokens

        :param tokens: tokens to refresh
        :type tokens: :class:`wxc_sdk.tokens.Tokens`
        :return: True -> tokens got updated
        """
        return self.integration.validate_tokens(tokens=tokens,min_lifetime_seconds=MIN_TOKEN_LIFETIME_SECONDS)

    def get_user_context_and_refresh(self, *, user_id: str) -> Optional[UserContext]:
        """
        Get user context for given user_id and try to refresh the access token if needed

        :param user_id: id of user to get context for
        :type user_id: str
        :return: user context
        :rtype: UserContext
        """
        user_context = self.get_user_context(user_id=user_id)
        if user_context is None:
            return None

        def refresh():
            """
            Refresh the access token in the user context.
            """
            log.debug(f'Token refresh for {user_id}')
            refreshed = self.token_refresh(tokens=user_context.tokens)
            if refreshed:
                log.debug(f'got new tokens for {user_id}')
                self.set_user_context(user_id=user_context.user_id, user_context=user_context)
            if not user_context.tokens.access_token:
                log.error(f'No access token for {user_id}')

        if user_context.tokens.remaining < MIN_TOKEN_LIFETIME_SECONDS:
            # consider refreshing tokens as soon as the remaining lifetime is less than 2 minutes
            if user_context.tokens.remaining < 0 or not user_context.tokens.access_token:
                # need immediate refresh
                refresh()
            else:
                # good for now but we need new tokens "soon": schedule a task
                log.debug(f'Initiate refresh of tokens for {user_id}')
                threading.Thread(target=refresh).start()
        return user_context


class RedisTokenManager(TokenManager):
    """
    Token Manager using Redis as backend
    """
    #: Redis key for set of active flow ids
    FLOW_SET = 'flows'

    #: Redis key for datetime of latest flow maintenance. This is used in :meth:`flow_maintenance_needed` to
    #: determine whether flow maintenance is needed
    FLOW_MAINTENANCE = 'flow-maintenance'

    #: prefix for Redis keys to store :class:`UserContext` for users. Full key is in the form
    #: of '{USER_KEY_PREFIX}-{user_id}'
    USER_KEY_PREFIX = 'user'

    #: Redis key for set of users IDs we have :class:`UserContext` for in Redis
    USER_SET = 'users'

    def flow_key(self, *, flow_id: str) -> str:
        """
        Redis key for a flow. Something like 'flows-{flow_id}'

        :param flow_id: OAuth flow id
        :type flow_id: str
        :return: Redis key for given flow id
        :rtype: str
        :meta private:
        """
        return f'{self.FLOW_SET}-{flow_id}'

    def user_key(self, *, user_id) -> str:
        """
        A Redis key for a given user ID

        :param user_id: user id to create a Redis key for. Something like 'user-{user_id}'
        :type user_id: str
        :return: Redis key
        :rtype: str
        :meta private:
        """
        return f'{self.USER_KEY_PREFIX}-{user_id}'

    class FlowState(BaseModel):
        """
        keep track of a pending OAuth flow. For each flow we keep track of the creation time. This time is used to
        garbage collect old flows if needed
        """
        #: user id the flow was created for
        user_id: str
        #: :class:`datetime.datetime` the flow was created at
        created: datetime.datetime = Field(default_factory=lambda: datetime.datetime.utcnow().replace(tzinfo=pytz.UTC))

    def __init__(self, bot_token: str, integration: Integration, redis_host: str = None, redis_url: str = None):
        """
        set up Redis token Manager

        :param bot_token: bot access token. Required to be able to send responses to the user
        :type bot_token: str
        :param integration: OAuth integration. Used to call the respective endpoints to obtain/refresh tokens
        :type integration:  :class:wxc_sdk.integration.Integration
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
        """
        :meta private:
        """
        # close redis connection
        if self.redis:
            self.redis.close()
            self.redis = None

    def flow_maintenance_needed(self, *, force: bool = False) -> bool:
        """
        Determine whether flow maintenance is needed; only once every 15 minutes

        :return:
        """
        try:
            latest_maintenance_str = self.redis.get(self.FLOW_MAINTENANCE) or b''
            latest_maintenance_str = latest_maintenance_str.decode()
            latest_maintenance = datetime.datetime.fromisoformat(latest_maintenance_str)
        except (ValueError, TypeError):
            latest_maintenance = None
        now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        if force or latest_maintenance is None or (now - latest_maintenance).total_seconds() > 900:
            # set current time as latest time of maintenance
            self.redis.set(self.FLOW_MAINTENANCE, now.isoformat())
            return True
        return False

    def flow_maintenance(self, *, force: bool = False, output: TextIOBase = None):
        """
        Garbage collection on existing flows if needed.

        :return:
        """
        output = output or StringIO()
        # Check if flow maintenance is required.
        if not self.flow_maintenance_needed(force=force):
            return
        log.debug('starting flow maintenance')
        now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        # iterate over all flows
        for flow_key in self.redis.smembers(self.FLOW_SET):
            flow_key = flow_key.decode()
            flow_state = self._get_flow_state(flow_key=flow_key)
            if force or not flow_state or ((now - flow_state.created).total_seconds() > 300):
                # candidate for deletion if flow is older than 5 minutes
                message = f'garbage collection for flow {flow_key}: {flow_state}'
                log.debug(message)
                print(f'Deleting flow {flow_key}: {flow_state and flow_state.created}', file=output)
                self.redis.srem(self.FLOW_SET, flow_key)
                if flow_state:
                    self.redis.delete(flow_key)
                # if
            # if not
        # for
        return

    def _get_flow_state(self, *, flow_key: str) -> Optional[FlowState]:
        """
        Get parsed flow state from Redis

        :param flow_key:
        :type flow_key: str
        :return: flow state
        """
        flow_state_str = self.redis.get(flow_key)
        if not flow_state_str:
            return None
        try:
            # Redis stores JSON representation of :class:`FlowState`. Try to deserialize.
            flow_state = RedisTokenManager.FlowState.parse_obj(json.loads(flow_state_str))
        except (json.JSONDecodeError, pydantic.PydanticTypeError, pydantic.ValidationError) as e:
            log.warning(f'failed to parse state for flow key {flow_key}: {e}')
            return None
        return flow_state

    def start_flow(self, *, user_id: str) -> str:
        """
        Register OAuth flow for a user

        :param user_id: id of user to start the flow for
        :type user_id: str
        :return: flow id, the flow id is used as state parameter in OAuth flow and allows to identify the flow when
            acting on the POST at the end of the OAuth flow
        """
        self.flow_maintenance()
        # random flow id for the OAuth flow
        flow_id = str(uuid.uuid4())

        # determine the Redis flow key based on the flow id.
        flow_key = self.flow_key(flow_id=flow_id)

        # initialize state for new flow
        flow_state = RedisTokenManager.FlowState(user_id=user_id).json()
        log.debug(f'start_flow: set({flow_key}, {flow_state})')

        # and store it in Redis
        self.redis.set(flow_key, flow_state)
        self.redis.sadd(self.FLOW_SET, flow_key)
        return flow_id

    def process_redirect(self, *, flow_id: str, code: str) -> str:
        """
        Process redirect at end of OAuth flow. New tokens are stored in user context

        :param flow_id: OAuth flow id
        :type flow_id: str
        :param code: code obtained from final URL in OAuth flow
        :type code: str
        :return: text for HTTP response
        :rtype: str
        """
        # determine Redis flow key for flow id and get the flow state from Redis
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

        # use the new tokens to get identity of authenticated user
        with WebexSimpleApi(tokens=tokens) as api:
            me = api.people.me()

        # we expect the authenticated user to be identical to the user who initiated the auth flow
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

        :param user_id: user id of user to store context for
        :type user_id: str
        :param user_context: context to store; if None then clear context for this user
        :type user_context: :class:`UserContext`
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
        :type user_id: str
        :return:
        :rtype: :class:`UserContext`
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

        return user_context


class YAMLTokenManager(TokenManager):
    """
    A TokenManager using a local YAML file to store user contexts. Flow state is stored within the instance. This
    only works if there is a single worker servicing the requests.
    """

    def __init__(self, bot_token: str, integration: Integration, yml_base: str):
        """

        :param bot_token: Bot token
        :type bot_token: str
        :param integration: Integration to use to obtain tokens
        :type integration: :class:`wxc_sdk.integration.Integration`
        :param yml_base: base name (no extension) for YAML file to use to persist state
        :type yml_base: str
        """
        super().__init__(bot_token=bot_token, integration=integration)
        self.yml_path = os.path.join(os.getcwd(), f'{yml_base}.yml')
        self._user_context: dict[str, UserContext] = dict()
        self._flows: dict[str, str] = dict()
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

        :param flow_id: OAuth flow id
        :param code: code obtained from final URL in OAuth flow
        :return: text for HTTP response
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
            authenticated_user = f'{me.display_name} ({me.emails[0]})'
            log.warning(f'process_redirect({flow_id}, {code}): tokens for wrong user: {authenticated_user}')
            api = WebexTeamsAPI(access_token=self.bot_token)
            api.messages.create(toPersonId=user_id,
                                text=f'tokens for wrong user: {authenticated_user}')

            return f'tokens for wrong user: {authenticated_user}'
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

        :param user_id: user id
        :type user_id: str
        :param user_context: user context; if None then clear the user context
        :type user_context: :class:`UserContext`
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
        :type user_id: str
        :return:
        :rtype: :class:`UserContext`
        """
        context = self._user_context.get(user_id)
        return context
