import pwd
import grp

from det_user_sync import SourceGroups, SourceUser, SourceUsers


DEFAULT_PASSWORD = "changeme"


def get_unix_groups(unix_group_names: str) -> SourceGroups:
    groups = SourceGroups()

    for unix_group_name in unix_group_names.split(","):
        groups[unix_group_name] = SourceUsers()

        group = grp.getgrnam(unix_group_name)

        for group_member in group.gr_mem:
            unix_user = pwd.getpwnam(group_member)

            user = SourceUser(
                username=unix_user.pw_name,
                uid=unix_user.pw_uid,
                gid=unix_user.pw_gid,
                unix_username=unix_user.pw_name,
                unix_groupname=str(unix_user.pw_gid),
                display_name=None,
                password=DEFAULT_PASSWORD
            )

            groups[unix_group_name].append(user)

    return groups
