from pydantic import BaseModel

from typing import Literal, Optional
import datetime
import pytz

__all__ = ['Tokens']


class Tokens(BaseModel):
    access_token: str
    expires_in: int
    expires_at: Optional[datetime.datetime]
    refresh_token: str
    refresh_token_expires_in: int
    refresh_token_expires_at: Optional[datetime.datetime]
    token_type: Literal['Bearer']

    def json(self, *args, **kwargs):
        exclude = kwargs.get('exclude', set())
        exclude.update(('expires_in', 'refresh_token_expires_in'))
        kwargs['exclude'] = exclude
        return super().json(*args, **kwargs)

    def update(self, new_tokes: 'Tokens'):
        self.access_token = new_tokes.access_token
        self.expires_in = new_tokes.expires_in
        self.expires_at = new_tokes.expires_at
        self.refresh_token = new_tokes.refresh_token
        self.refresh_token_expires_in = new_tokes.refresh_token_expires_in
        self.refresh_token_expires_at = new_tokes.refresh_token_expires_at

    def set_expiration(self):
        """
        Set expiration based on current time
        :return:
        """
        now = datetime.datetime.utcnow()
        now = now.replace(tzinfo=pytz.UTC)
        if not self.expires_at:
            delta = datetime.timedelta(seconds=self.expires_in)
            self.expires_at = now + delta
        if not self.refresh_token_expires_at:
            delta = datetime.timedelta(seconds=self.refresh_token_expires_in)
            self.refresh_token_expires_at = now + delta

    @property
    def remaining(self) -> int:
        """
        get seconds remaining
        :return:
        """
        if not self.access_token:
            return 0
        now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        diff = self.expires_at - now
        diff: datetime.timedelta
        diff = int(diff.total_seconds())
        return diff

    @property
    def needs_refresh(self):
        return not self.access_token or self.remaining < 300
