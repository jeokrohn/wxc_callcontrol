"""
Telephony types and API
"""

from .calls import CallsApi
from .schedules import ScheduleAPI
from .paging import PagingAPI
from .huntgroup import HuntGroupAPI
from .callqueue import CallQueueAPI
from ..api_child import ApiChild

__all__ = ['TelephonyApi']


class TelephonyApi(ApiChild, base='telephony'):
    """
    The telephony API. Child of :class:`WebexSimpleApi`
    """

    def __init__(self, session):
        super().__init__(session=session)
        #: calls API :class:`calls.CallsApi`
        self.calls = CallsApi(session=session)
        #: schedule API: class:`schedules.ScheduleAPI`
        self.schedules = ScheduleAPI(session=session)
        #: paging group API: class:`paging.PagingAPI`
        self.paging = PagingAPI(session=session)
        #: huntgroup API: class:`huntgroup.HuntGroupAPI`
        self.huntgroup = HuntGroupAPI(session=session)
        #: call queue API: class:`callqueue.CallQueueAPI`
        self.callqueue = CallQueueAPI(session=session)
