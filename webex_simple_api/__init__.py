"""
Simple API implementing the Webex API endpoints required for the Webex Calling call control demo bot
"""
import logging
import os
from typing import Union

from tokens import Tokens
from .api_child import ApiChild
from .base import ApiModel, webex_id_to_uuid, to_camel
from .licenses import LicensesAPI
from .locations import LocationsAPI
from .people import PeopleApi
from .person_settings import PersonSettingsApi
from .rest import RestSession, StrOrDict
from .telephony import TelephonyApi
from .webhook import WebhookApi

__all__ = ['WebexSimpleApi']

log = logging.getLogger(__name__)


class WebexSimpleApi:
    """
    A simple API implementing the endpoints needed for the simple demo
    """

    def __init__(self, *, tokens: Union[str, Tokens] = None, concurrent_requests: int = 10):
        if isinstance(tokens, str):
            tokens = Tokens(access_token=tokens)
        elif tokens is None:
            tokens = os.getenv('WEBEX_ACCESS_TOKEN')
            if tokens is None:
                raise ValueError('if no access token is passed, then a valid access token has to be present in '
                                 'WEBEX_ACCESS_TOKEN environment variable')
            tokens = Tokens(access_token=tokens)
        #: :class:`rest.RestSession` used for all API requests
        self.session = RestSession(tokens=tokens, concurrent_requests=concurrent_requests)
        #: Licenses API :class:`licenses.LicensesAPI`
        self.licenses = LicensesAPI(session=self.session)
        #: Location API :class:`locations.LocationsApi`
        self.locations = LocationsAPI(session=self.session)
        #: Person settings API: :class:`person_settings.PersonSettingsApi`
        self.person_settings = PersonSettingsApi(session=self.session)
        #: People API :class:`people.PeopleApi`
        self.people = PeopleApi(session=self.session)
        #: Telephony API :class:`telephony.TelephonyApi`
        self.telephony = TelephonyApi(session=self.session)
        #: Webhooks API :class:`webhook.WebhookApi`
        self.webhook = WebhookApi(session=self.session)

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
