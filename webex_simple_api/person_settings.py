"""
Person settings
"""
import json
import os.path
from enum import Enum
from io import BufferedReader
from typing import Optional, Union, List
from requests_toolbelt.multipart.encoder import MultipartEncoder

from pydantic import Field

from .api_child import ApiChild
from .base import ApiModel, to_camel

__all__ = ['BargeSettings', 'CallForwardingCommon', 'CallForwardingAlways', 'CallForwardingNoAnswer', 'CallForwarding',
           'ForwardingSetting', 'InterceptTypeIncoming', 'Greeting', 'InterceptNumber', 'InterceptAnnouncements',
           'InterceptSettingIncoming', 'InterceptTypeOutgoing', 'InterceptSettingOutgoing', 'InterceptSetting',
           'Record', 'NotificationType', 'NotificationRepeat', 'Notification',
           'CallRecordingSetting', 'CallerIdSelectedType', 'CustomNumberType', 'CustomNumberInfo',
           'ExternalCallerIdNamePolicy', 'CallerId',
           'PersonSettingsApi']


class BargeSettings(ApiModel):
    """
    Barge settings
    """
    #: indicates if the Barge In feature is enabled.
    enabled: bool
    #: Indicates that a stutter dial tone will be played when a person is barging in on the active call.
    tone_enabled: bool


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


class InterceptTypeIncoming(str, Enum):
    #: incoming calls are intercepted. Incoming calls are routed as destination and voicemail specify.
    intercept_all = 'INTERCEPT_ALL'
    #: Incoming calls are not intercepted.
    allow_all = 'ALLOW_ALL'


class Greeting(str, Enum):
    """
    DEFAULT indicates that a system default message will be placed when incoming calls are intercepted.
    """
    #: A custom will be placed when incoming calls are intercepted.
    custom = 'CUSTOM'
    #: A System default message will be placed when incoming calls are intercepted.
    default = 'DEFAULT'


class InterceptNumber(ApiModel):
    """
    Information about a number announcement.
    """
    #: If true, the caller will hear this number when the call is intercepted.
    enabled: bool
    #: number caller will hear announced.
    destination: Optional[str]


class InterceptAnnouncements(ApiModel):
    """
    Settings related to how incoming calls are handled when the intercept feature is enabled.
    """
    greeting: Greeting
    #: Filename of custom greeting, will be an empty string if no custom greeting has been uploaded.
    file_name: Optional[str]
    #: Information about the new number announcement.
    new_number: InterceptNumber
    #: Information about how the call will be handled if zero (0) is pressed.
    zero_transfer: InterceptNumber

    @staticmethod
    def default() -> 'InterceptAnnouncements':
        return InterceptAnnouncements(greeting=Greeting.default, new_number=InterceptNumber(enabled=False),
                                      zero_transfer=InterceptNumber(enabled=False))


class InterceptSettingIncoming(ApiModel):
    """
    Settings related to how incoming calls are handled when the intercept feature is enabled.
    """
    intercept_type: InterceptTypeIncoming = Field(alias='type')
    #: If true, the destination will be the person's voicemail.
    voicemail_enabled: bool
    #: Settings related to how incoming calls are handled when the intercept feature is enabled.
    announcements: InterceptAnnouncements

    @staticmethod
    def default() -> 'InterceptSettingIncoming':
        return InterceptSettingIncoming(intercept_type=InterceptTypeIncoming.intercept_all, voicemail_enabled=False,
                                        announcements=InterceptAnnouncements.default())


class InterceptTypeOutgoing(str, Enum):
    #: Outgoing calls are routed as destination and voicemail specify.
    intercept_all = 'INTERCEPT_ALL'
    #: Only non-local calls are intercepted.
    allow_local_only = 'ALLOW_LOCAL_ONLY'


class InterceptSettingOutgoing(ApiModel):
    intercept_type: InterceptTypeOutgoing = Field(alias='type')
    #: If true, when the person attempts to make an outbound call, a system default message is played and the call is
    #: made to the destination phone number
    transfer_enabled: bool
    #: Number to which the outbound call be transferred.
    destination: Optional[str]

    @staticmethod
    def default() -> 'InterceptSettingOutgoing':
        return InterceptSettingOutgoing(intercept_type=InterceptTypeOutgoing.intercept_all, transfer_enabled=False)


class InterceptSetting(ApiModel):
    """
    A person's call intercept settings
    """
    #: true if call intercept is enabled.
    enabled: bool
    #: Settings related to how incoming calls are handled when the intercept feature is enabled.
    incoming: InterceptSettingIncoming
    #: Settings related to how outgoing calls are handled when the intercept feature is enabled.
    outgoing: InterceptSettingOutgoing

    @staticmethod
    def default() -> 'InterceptSetting':
        return InterceptSetting(enabled=False,
                                incoming=InterceptSettingIncoming.default(),
                                outgoing=InterceptSettingOutgoing.default())


class Record(str, Enum):
    #: Incoming and outgoing calls will be recorded with no control to start, stop, pause, or resume.
    always = 'Always'
    #: Calls will not be recorded.
    never = 'Never'
    #: Calls are always recorded, but user can pause or resume the recording. Stop recording is not supported.
    always_w_pause_resume = 'Always with Pause/Resume'
    #: Records only the portion of the call after the recording start (*44) has been entered. Pause, resume, and
    #: stop controls are supported.
    on_demand = 'On Demand with User Initiated Start'


class NotificationType(str, Enum):
    """
    Type of pause/resume notification.
    """
    #: No notification sound played when call recording is paused or resumed.
    none = 'None'
    #: A beep sound is played when call recording is paused or resumed.
    beep = 'Beep'
    #: A verbal announcement is played when call recording is paused or resumed.
    play_announcement = 'Play Announcement'


class NotificationRepeat(ApiModel):
    """
    Beep sound plays periodically.
    """
    #: Interval at which warning tone "beep" will be played. This interval is an integer from 10 to 1800 seconds
    interval: int
    #: true when ongoing call recording tone will be played at the designated interval. false indicates no warning tone
    # will be played
    enabled: bool


class Notification(ApiModel):
    #: Type of pause/resume notification.
    notification_type: NotificationType = Field(alias='type')
    #: true when the notification feature is in effect. false indicates notification is disabled.
    enabled: bool


class CallRecordingSetting(ApiModel):
    #: true if call recording is enabled.
    enabled: bool
    #: Specified under which scenarios calls will be recorded.
    record: Record
    #: When true, voicemail messages are also recorded.
    record_voicemail_enabled: bool
    #: When enabled, an announcement is played when call recording starts and an announcement is played when call
    #: recording ends.
    start_stop_announcement_enabled: bool
    #: Pause/resume notification settings.
    notification: Notification
    #: Beep sound plays periodically.
    repeat: NotificationRepeat
    #: Name of the service provider providing call recording service.
    service_provider: Optional[str]
    #: Group utilized by the service provider providing call recording service
    external_group: Optional[str]
    #: Unique person identifier utilized by the service provider providing call recording service.
    external_identifier: Optional[str]

    @staticmethod
    def default() -> 'CallRecordingSetting':
        """
        Default settings for a user
        """
        return CallRecordingSetting(enabled=False,
                                    record=Record.never,
                                    record_voicemail_enabled=False,
                                    start_stop_announcement_enabled=False,
                                    notification=Notification(notification_type=NotificationType.none,
                                                              enabled=False),
                                    repeat=NotificationRepeat(interval=15,
                                                              enabled=False))


class CallerIdSelectedType(str, Enum):
    """
    Allowed types for the selected field.
    """
    #: Outgoing caller ID will show the caller's direct line number and/or extension.
    direct_line = 'DIRECT_LINE'
    #: Outgoing caller ID will show the main number for the location.
    location_number = 'LOCATION_NUMBER'
    #: Outgoing caller ID will show the mobile number for this person.
    mobile_number = 'MOBILE_NUMBER'
    #: Outgoing caller ID will show the value from the customNumber field.
    custom = 'CUSTOM'


class CustomNumberType(str, Enum):
    """
    EXTERNAL if the custom caller ID number is external, otherwise INTERNAL.
    """
    internal = 'INTERNAL'
    external = 'EXTERNAL'


class CustomNumberInfo(ApiModel):
    #: EXTERNAL if the custom caller ID number is external, otherwise INTERNAL.
    custom_number_type: CustomNumberType = Field(alias='type')
    #: First name of custom caller ID number.
    first_name: str
    #: Last name of custom caller ID number.
    last_name: str


class ExternalCallerIdNamePolicy(str, Enum):
    """
    Designates which type of External Caller Id Name policy is used. Default is DIRECT_LINE.
    """
    #: Outgoing caller ID will show the caller's direct line name
    direct_line = 'DIRECT_LINE'
    #: Outgoing caller ID will show the Site Name for the location.
    location = 'LOCATION'
    #: Outgoing caller ID will show the value from the custom_external_caller_id_name field.
    other = 'OTHER'


class CallerId(ApiModel):
    #: Allowed types for the selected field.
    caller_id_types: List[CallerIdSelectedType] = Field(alias='types')
    #: Which type of outgoing Caller ID will be used.
    selected: CallerIdSelectedType
    #: Direct number which will be shown if DIRECT_LINE is selected.
    direct_number: Optional[str]
    #: Extension number which will be shown if DIRECT_LINE is selected.
    extension_number: Optional[str]
    #: Location number which will be shown if LOCATION_NUMBER is selected.
    location_number: Optional[str]
    #: True id the location number is toll free
    toll_free_location_number: Optional[bool]  # TODO: file documentation defect
    #: Mobile number which will be shown if MOBILE_NUMBER is selected.
    mobile_number: Optional[str]
    #: This value must be an assigned number from the person's location.
    custom_number: Optional[str]
    #: Information about the custom caller ID number.
    custom_number_info: Optional[CustomNumberInfo]
    #: Person's Caller ID first name. Characters of %, +, ``, " and Unicode characters are not allowed.
    first_name: str
    #: Person's Caller ID last name. Characters of %, +, ``, " and Unicode characters are not allowed.
    last_name: str
    #: block caller id in forwarded calls
    block_in_forward_calls_enabled: bool  # TODO: file documentation defect, not documented
    #: Designates which type of External Caller Id Name policy is used. Default is DIRECT_LINE.
    external_caller_id_name_policy: Optional[ExternalCallerIdNamePolicy]
    #: Custom External Caller Name, which will be shown if External Caller Id Name is OTHER.
    custom_external_caller_id_name: Optional[str]
    # TODO: file documentation defect, value seems to be present if
    #  caller id is set to location number
    #: location external caller ID name
    location_external_caller_id_name: Optional[str]

    def configure_params(self) -> dict:
        """
        Get a dict with values that can be used to configure the caller id settings

        :return: dict
        :rtype: dict
        """
        data = self.dict()
        to_keep = {
            'selected',
            'custom_number',
            'first_name',
            'last_name',
            'external_caller_id_name_policy',
            'custom_external_caller_id_name'}
        result = {k: v for k, v in data.items()
                  if v is not None and k in to_keep}
        return result


class PersonSettingsApi(ApiChild, base='people'):
    """
    API for all user level settings
    """

    def f_ep(self, *, person_id: str, path: str = None) -> str:
        """
        person specific feature endpoint like v1/people/{uid}/features/....

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param path: path in the endpoint after the feature base URL
        :type path: str
        :return: full endpoint
        :rtype: str
        """
        path = path and f'/{path}' or ''
        return self.session.ep(f'people/{person_id}/features{path}')

    def barge_read(self, person_id: str, org_id: str = None) -> BargeSettings:
        """
        Retrieve a Person's Barge In Settings

        The Barge In feature enables you to use a Feature Access Code (FAC) to answer a call that was directed to
        another subscriber, or barge-in on the call if it was already answered. Barge In can be used across locations.

        This API requires a full, user, or read-only administrator auth token with a scope of spark-admin:people_read
        or a user auth token with spark:people_read scope can be used by a person to read their own settings.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        :return: barge settings for specific user
        :rtype: BargeSettings
        """
        ep = self.f_ep(person_id=person_id, path='bargeIn')
        params = org_id and {'orgId': org_id} or None
        return BargeSettings.parse_obj(self.get(ep, params=params))

    def barge_configure(self, person_id: str, barge_settings: BargeSettings, org_id: str = None):
        """
        Configure a Person's Barge In Settings

        The Barge In feature enables you to use a Feature Access Code (FAC) to answer a call that was directed to
        another subscriber, or barge-in on the call if it was already answered. Barge In can be used across locations.

        This API requires a full or user administrator auth token with the spark-admin:people_write scope or a user
        auth token with spark:people_write scope can be used by a person to update their own settings.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param barge_settings: new setting to be applied
        :type barge_settings: BargeSettings
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        """
        ep = self.f_ep(person_id=person_id, path='bargeIn')
        params = org_id and {'orgId': org_id} or None
        self.put(ep, params=params, data=barge_settings.json())

    def forwarding_read(self, person_id: str, org_id: str = None) -> ForwardingSetting:
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

    def forwarding_configure(self, person_id: str, forwarding: ForwardingSetting, org_id: str = None):
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

    def call_intercept_read(self, person_id: str, org_id: str = None) -> InterceptSetting:
        """
        Read Call Intercept Settings for a Person

        Retrieves Person's Call Intercept Settings

        The intercept feature gracefully takes a person’s phone out of service, while providing callers with
        informative announcements and alternative routing options. Depending on the service configuration, none,
        some, or all incoming calls to the specified person are intercepted. Also depending on the service
        configuration, outgoing calls are intercepted or rerouted to another location.

        This API requires a full, user, or read-only administrator auth token with a scope of spark-admin:people_read.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        :return: user's call intercept settings
        :rtype: InterceptSetting
        """
        ep = self.f_ep(person_id=person_id, path='intercept')
        params = org_id and {'orgId': org_id} or None
        return InterceptSetting.parse_obj(self.get(ep, params=params))

    def call_intercept_configure(self, person_id: str, intercept: InterceptSetting, org_id: str = None):
        """
        Configure Call Intercept Settings for a Person
        Configures a Person's Call Intercept Settings

        The intercept feature gracefully takes a person’s phone out of service, while providing callers with
        informative announcements and alternative routing options. Depending on the service configuration, none, some,
        or all incoming calls to the specified person are intercepted. Also depending on the service configuration,
        outgoing calls are intercepted or rerouted to another location.

        This API requires a full or user administrator auth token with the spark-admin:people_write scope.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param intercept: new intercept settings
        :type intercept: InterceptSetting
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        """
        ep = self.f_ep(person_id=person_id, path='intercept')
        params = org_id and {'orgId': org_id} or None
        data = json.loads(intercept.json())
        try:
            # remove attribute not present in update
            data['incoming']['announcements'].pop('fileName', None)
        except KeyError:
            pass
        self.put(ep, params=params, json=data)

    def call_intercept_greeting(self, person_id: str, content: Union[BufferedReader, str],
                                upload_as: str = None, org_id: str = None):
        """
        Configure Call Intercept Greeting for a Person

        Configure a Person's Call Intercept Greeting by uploading a Waveform Audio File Format, .wav, encoded audio
        file.

        Your request will need to be a multipart/form-data request rather than JSON, using the audio/wav Content-Type.

        This API requires a full or user administrator auth token with the spark-admin:people_write scope or a user
        auth token with spark:people_write scope can be used by a person to update their settings.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param content: the file to be uploaded, can be a path to a file or a buffered reader (opened file); if a
            reader referring to an open file is passed then make sure to open the file as binary b/c otherwise the
            content length might be calculated wrong
        :type content: Union[BufferedReader, str]
        :param upload_as: filename for the content. Only required if content is a reader; has to be a .wav file name.
        :type upload_as: str
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        """
        if isinstance(content, str):
            upload_as = os.path.basename(content)
            content = open(content, mode='rb')
            must_close = True
            pass
        else:
            must_close = False
            # an existing reader
            if not upload_as:
                raise ValueError('upload_as is required')
        encoder = MultipartEncoder(fields={'file': (upload_as, content, 'audio/wav')})
        ep = self.f_ep(person_id=person_id, path='intercept/actions/announcementUpload/invoke')
        try:
            self.post(ep, data=encoder, headers={'Content-Type': encoder.content_type})
        finally:
            if must_close:
                content.close()
        return

    def call_recording_read(self, person_id: str, org_id: str = None) -> CallRecordingSetting:
        """
        Read Call Recording Settings for a Person
        Retrieve a Person's Call Recording Settings

        The Call Recording feature provides a hosted mechanism to record the calls placed and received on the Carrier
        platform for replay and archival. This feature is helpful for quality assurance, security, training, and more.

        This API requires a full or user administrator auth token with the spark-admin:people_write scope.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        """
        ep = self.f_ep(person_id=person_id, path='callRecording')
        params = org_id and {'orgId': org_id} or None
        return CallRecordingSetting.parse_obj(self.get(ep, params=params))

    def call_recording_configure(self, person_id: str, recording: CallRecordingSetting, org_id: str = None):
        """
        Configure Call Recording Settings for a Person
        Configure a Person's Call Recording Settings

        The Call Recording feature provides a hosted mechanism to record the calls placed and received on the Carrier
        platform for replay and archival. This feature is helpful for quality assurance, security, training, and more.

        This API requires a full or user administrator auth token with the spark-admin:people_write scope.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param recording: the new recording settings
        :type recording: CallRecordingSetting
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        """
        ep = self.f_ep(person_id=person_id, path='callRecording')
        params = org_id and {'orgId': org_id} or None
        data = json.loads(recording.json())
        for key in ['serviceProvider', 'externalGroup', 'externalIdentifier']:
            # remove attribute not present in update
            data.pop(key, None)
        self.put(ep, params=params, json=data)

    def caller_id_read(self, person_id: str, org_id: str = None) -> CallerId:
        """
        Retrieve a Person's Caller ID Settings

        Caller ID settings control how a person’s information is displayed when making outgoing calls.

        This API requires a full, user, or read-only administrator auth token with a scope of spark-admin:people_read
        or a user auth token with spark:people_read scope can be used by a person to read their settings.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        """
        ep = self.f_ep(person_id=person_id, path='callerId')
        params = org_id and {'orgId': org_id} or None
        return CallerId.parse_obj(self.get(ep, params=params))

    def caller_id_configure(self, person_id: str, org_id: str = None,
                            selected: CallerIdSelectedType = None,
                            custom_number: str = None,
                            first_name: str = None,
                            last_name: str = None,
                            external_caller_id_name_policy: ExternalCallerIdNamePolicy = None,
                            custom_external_caller_id_name: str = None):
        """
        Configure Caller ID Settings for a Person
        Configure a Person's Caller ID Settings

        Caller ID settings control how a person’s information is displayed when making outgoing calls.

        This API requires a full or user administrator auth token with the spark-admin:people_write scope or a user
        auth token with spark:people_write scope can be used by a person to update their own settings.

        :param person_id: Unique identifier for the person.
        :type person_id: str
        :param org_id: Person is in this organization. Only admin users of another organization (such as partners)
            may use this parameter as the default is the same organization as the token used to access API.
        :type org_id: str
        :param selected: Which type of outgoing Caller ID will be used.
        :type selected: CallerIdSelectedType
        :param custom_number: This value must be an assigned number from the person's location.
        :type custom_number: str
        :param first_name: Person's Caller ID first name. Characters of %, +, ``, " and Unicode characters are not
            allowed.

        :type first_name: str
        :param last_name: Person's Caller ID last name. Characters of %, +, ``, " and Unicode characters are not
            allowed.
        :type last_name: str
        :param external_caller_id_name_policy: Designates which type of External Caller Id Name policy is used.
            Default is DIRECT_LINE.
        :type external_caller_id_name_policy: ExternalCallerIdNamePolicy
        :param custom_external_caller_id_name: Custom External Caller Name, which will be shown if External Caller Id
            Name is OTHER.
        :type custom_external_caller_id_name: str
        """
        data = {to_camel(k): v for i, (k, v) in enumerate(locals().items())
                if i > 2 and v is not None}
        params = org_id and {'orgId': org_id} or None
        ep = self.f_ep(person_id=person_id, path='callerId')
        self.put(ep, params=params, json=data)
