"""
Call forwarding API
"""
import json
from typing import Optional

from .common import PersonSettingsApiChild
from ..base import ApiModel

__all__ = ['CallForwardingCommon', 'CallForwardingAlways', 'CallForwardingNoAnswer', 'CallForwarding',
           'ForwardingSetting', 'ForwardingApi']


class CallForwardingCommon(ApiModel):
    """
    Common call forwarding settings
    """
    #: call forwarding is enabled or disabled.
    enabled: bool
    #: Destination for call forwarding.
    destination: Optional[str]
    #: Indicates enabled or disabled state of sending incoming calls to voicemail when the destination is an internal
    #: phone number and that number has the voicemail service enabled.
    destination_voicemail_enabled: Optional[bool]

    @staticmethod
    def default() -> 'CallForwardingCommon':
        return CallForwardingCommon(enabled=False, destination='', destination_voicemail_enabled=False)


class CallForwardingAlways(CallForwardingCommon):
    """
    Settings for forwarding all incoming calls to the destination you choose.
    """
    #: If true, a brief tone will be played on the person’s phone when a call has been forwarded.
    ring_reminder_enabled: bool

    @staticmethod
    def default() -> 'CallForwardingAlways':
        return CallForwardingAlways(enabled=False, destination='', destination_voicemail_enabled=False,
                                    ring_reminder_enabled=False)


class CallForwardingNoAnswer(CallForwardingCommon):
    #: Number of rings before the call will be forwarded if unanswered.
    number_of_rings: int
    # System-wide maximum number of rings allowed for numberOfRings setting.
    system_max_number_of_rings: Optional[int]

    @staticmethod
    def default() -> 'CallForwardingNoAnswer':
        return CallForwardingNoAnswer(enabled=False, destination='', destination_voicemail_enabled=False,
                                      number_of_rings=3)


class CallForwarding(ApiModel):
    """
    Settings related to "Always", "Busy", and "No Answer" call forwarding.
    """
    #: Settings for forwarding all incoming calls to the destination you choose.
    always: CallForwardingAlways
    #: Settings for forwarding all incoming calls to the destination you chose while the phone is in use or the person
    #: is busy.
    busy: CallForwardingCommon
    #: Settings for forwarding which only occurs when you are away or not answering your phone.
    no_answer: CallForwardingNoAnswer

    @staticmethod
    def default() -> 'CallForwarding':
        return CallForwarding(always=CallForwardingAlways.default(),
                              busy=CallForwardingCommon.default(),
                              no_answer=CallForwardingNoAnswer.default())


class ForwardingSetting(ApiModel):
    """
    A person's call forwarding setting
    """
    #: Settings related to "Always", "Busy", and "No Answer" call forwarding.
    call_forwarding: CallForwarding
    #: Settings for sending calls to a destination of your choice if your phone is not connected to the network for
    #: any reason, such as power outage, failed Internet connection, or wiring problem.
    business_continuity: CallForwardingCommon

    @staticmethod
    def default() -> 'ForwardingSetting':
        return ForwardingSetting(call_forwarding=CallForwarding.default(),
                                 business_continuity=CallForwardingCommon.default())


class ForwardingApi(PersonSettingsApiChild, base='people'):
    """
    Api for person's call forwarding settings
    """

    def read(self, person_id: str, org_id: str = None) -> ForwardingSetting:
        """
        Retrieve a Person's Call Forwarding Settings

        Three types of call forwarding are supported:

        * Always – forwards all incoming calls to the destination you choose.

        * When busy – forwards all incoming calls to the destination you chose while the phone is in use or the person
          is busy.

        * When no answer – forwarding only occurs when you are away or not answering your phone.

        In addition, the Business Continuity feature will send calls to a destination of your choice if your phone is
        not connected to the network for any reason, such as power outage, failed Internet connection, or wiring problem

        This API requires a full, user, or read-only administrator auth token with a scope of spark-admin:people_read
        or a user auth token with spark:people_read scope can be used by a person to read their own settings.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        :return: user's forwarding settings
        :rtype: ForwardingSetting
        """
        ep = self.f_ep(person_id=person_id, path='callForwarding')
        params = org_id and {'orgId': org_id} or None
        return ForwardingSetting.parse_obj(self.get(ep, params=params))

    def configure(self, person_id: str, forwarding: ForwardingSetting, org_id: str = None):
        """
        Configure a Person's Call Forwarding Settings

        Three types of call forwarding are supported:

        * Always – forwards all incoming calls to the destination you choose.

        * When busy – forwards all incoming calls to the destination you chose while the phone is in use or the person
          is busy.

        * When no answer – forwarding only occurs when you are away or not answering your phone.

        In addition, the Business Continuity feature will send calls to a destination of your choice if your phone is
        not connected to the network for any reason, such as power outage, failed Internet connection, or wiring problem

        This API requires a full or user administrator auth token with the spark-admin:people_write scope or a user
        auth token with spark:people_write scope can be used by a person to update their settings.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param forwarding: new forwarding settings
        :type forwarding: ForwardingSetting
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        """
        ep = self.f_ep(person_id=person_id, path='callForwarding')
        params = org_id and {'orgId': org_id} or None
        data = json.loads(forwarding.json())
        try:
            # remove attribute not present in update
            data['callForwarding']['noAnswer'].pop('systemMaxNumberOfRings', None)
        except KeyError:
            pass
        self.put(ep, params=params, json=data)