from typing import Optional
import base64
from pydantic import BaseModel


def webex_id_to_uuid(webex_id: Optional[str]) -> Optional[str]:
    """
    Convert a webex id as used by the public APIs to a UUID

    :param webex_id: base 64 encoded id as used by public APIs
    :type webex_id: str
    :return: ID in uuid format
    """
    return webex_id and base64.b64decode(f'{webex_id}==').decode().split('/')[-1]


def to_camel(s: str) -> str:
    """
    Convert snake case variable name to camel case
    log_id -> logId

    :param s: snake case variable name
    :return: Camel case name
    """
    return ''.join(w.title() if i else w for i, w in enumerate(s.split('_')))


class ApiModel(BaseModel):
    """
    Base for all models used by the APIs
    """

    class Config:
        alias_generator = to_camel  # alias is camelcase version of attribute name
        allow_population_by_field_name = True
        extra = 'forbid'
        # set to forbid='forbid' to raise exceptions on schema error

    def json(self, *args, exclude_unset=True, by_alias=True, **kwargs) -> str:
        return super().json(*args, exclude_unset=exclude_unset, by_alias=by_alias, **kwargs)

