import grp
import pwd

import det_user_sync

DEFAULT_PASSWORD = "changeme"


def get_unix_groups(unix_group_names: list) -> det_user_sync.SourceGroups:
    groups = det_user_sync.SourceGroups()

    for unix_group_name in unix_group_names:
        groups[unix_group_name] = det_user_sync.SourceUsers()

        group = grp.getgrnam(unix_group_name)

        for group_member in group.gr_mem:
            unix_user = pwd.getpwnam(group_member)

            user = det_user_sync.SourceUser(
                username=unix_user.pw_name,
                uid=unix_user.pw_uid,
                gid=unix_user.pw_gid,
                unix_username=unix_user.pw_name,
                unix_groupname=str(unix_user.pw_gid),
                display_name="",
                password=DEFAULT_PASSWORD,
            )

            groups[unix_group_name].append(user)

    return groups
