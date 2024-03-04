import csv

from det_user_sync import SourceUser, SourceUsers, SourceGroups


def parse_userlist_csv(filepath: str) -> SourceGroups:
    required_fields = ["groupname", "username", "uid", "gid"]
    groups = SourceGroups()

    with open(filepath, "r") as csvfile:
        for ii, row in enumerate(csv.DictReader(csvfile)):
            for required_field in required_fields:
                if row.get(required_field) is None:
                    raise ValueError(
                        "Could not find required field '{required_field}' in row {ii}: {row}"
                    )

            if row["groupname"] not in groups:
                groups[row["groupname"]] = SourceUsers()

            user = SourceUser(
                username=row["username"],
                uid=int(row["uid"]),
                gid=int(row["gid"])
            )

            groups[row["groupname"]].append(user)

    return groups
