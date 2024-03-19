import dataclasses
from typing import Optional

from determined.common import api


@dataclasses.dataclass
class SourceUser:
    username: str
    uid: int
    gid: int
    unix_username: str
    unix_groupname: str
    display_name: str
    password: Optional[str] = None


SourceUsers = list[SourceUser]
SourceGroups = dict[str, SourceUsers]
v1UsersMap = dict[str, api.bindings.v1User]
v1GroupList = list[api.bindings.v1Group]
