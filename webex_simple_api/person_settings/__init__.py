"""
Person settings
"""

from .barge import *
from .call_intercept import *
from .call_recording import *
from .caller_id import *
from .forwarding import *
from .dnd import *
from ..api_child import ApiChild
from ..rest import RestSession


class PersonSettingsApi(ApiChild, base='people'):
    """
    API for all user level settings
    """

    def __init__(self, session: RestSession):
        super().__init__(session)
        self.caller_id = CallerIdApi(session)
        self.call_recording = CallRecordingApi(session)
        self.call_intercept = CallInterceptApi(session)
        self.forwarding = ForwardingApi(session)
        self.barge = BargeApi(session)
        self.dnd = DndApi(session)
        # TODO: voicemail settings
