import csv

import det_user_sync


def parse_userlist_csv(args: list) -> det_user_sync.SourceGroups:
    filepath = args[0]

    required_fields = [
        "groupname",
        "username",
        "uid",
        "gid",
        "unix_username",
        "unix_groupname",
        "display_name",
    ]

    groups = det_user_sync.SourceGroups()

    with open(filepath, "r") as csvfile:
        for row in csv.DictReader(csvfile):
            for required_field in required_fields:
                if row.get(required_field) is None:
                    raise ValueError(
                        "Could not find required field '{required_field}' in row {ii}: {row}"
                    )

            if row["groupname"] not in groups:
                groups[row["groupname"]] = det_user_sync.SourceUsers()

            user = det_user_sync.SourceUser(
                username=row["username"],
                uid=int(row["uid"]),
                gid=int(row["gid"]),
                unix_username=row["unix_username"],
                unix_groupname=row["unix_groupname"],
                display_name=row["display_name"],
                password=row["password"],
            )

            groups[row["groupname"]].append(user)

    return groups
