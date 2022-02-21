"""
Simple API implementing the Webex API endpoints required for the Webex Calling call control demo bot
"""
import logging

from tokens import Tokens
from .api_child import ApiChild
from .base import ApiModel, webex_id_to_uuid, to_camel
from .people import PeopleApi
from .rest import RestSession, StrOrDict
from .telephony import TelephonyApi
from .webhook import WebhookApi

__all__ = ['WebexSimpleApi']

log = logging.getLogger(__name__)


class WebexSimpleApi:
    """
    A simple API implementing the endpoints needed for the simple demo
    """

    def __init__(self, tokens: Tokens):
        self._tokens = tokens
        self.session = RestSession(tokens=tokens)
        self.people = PeopleApi(session=self.session)  #: People API :class:`people.PeopleApi`
        self.webhook = WebhookApi(session=self.session)  #: Webhook API :class:`webhook.WebhookApi`
        self.telephony = TelephonyApi(session=self.session)  #: Telephoy API :class:`telephony.TelephonyApi`

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
