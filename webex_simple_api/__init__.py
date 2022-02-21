"""
Simple API implementing the Webex API endpoints required for the Webex Calling call control demo bot
"""
import logging

from tokens import Tokens
from .api_child import ApiChild
from .base import ApiModel, webex_id_to_uuid, to_camel
from .licenses import LicensesAPI
from .locations import LocationsAPI
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
        self.licenses = LicensesAPI(session=self.session)   #: Licenses API :class:`licenses.LicensesAPI`
        self.locations = LocationsAPI(session=self.session)   #: Location API :class:`locations.LocationsApi`
        self.people = PeopleApi(session=self.session)  #: People API :class:`people.PeopleApi`
        self.telephony = TelephonyApi(session=self.session)  #: Telephony API :class:`telephony.TelephonyApi`
        self.webhook = WebhookApi(session=self.session)  #: Webhook API :class:`webhook.WebhookApi`

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
