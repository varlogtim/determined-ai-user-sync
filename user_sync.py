#!/usr/bin/env python3
# XXX Need python >3.9
import argparse
import dataclasses
import logging
import os
from typing import Optional

from determined import cli
from determined.common import api
from determined.experimental import client

# XXX There is a question of where the user-groups we should
# XXX Not doing a report
# XXX Potentially need a disable user limit?
# XXX need to implement --dry-run=false


@dataclasses.dataclass
class User:
    username: str
    uid: int
    gid: int
    group_name: Optional[str] = "Unknown"


UserList = list[User]
UserGroups = dict[str, UserList]
v1UsersMap = dict[str, api.bindings.v1User]
v1GroupList = list[api.bindings.v1Group]


class UserSync:
    def __init__(self, dry_run: bool = True) -> None:
        self._dry_run = dry_run
        self._session: api.Session = None

    def sync_users(self) -> None:
        self._login()
        # XXX Read through this and handle exceptions

        source_users_groups: UserGroups = parse_userlist_csv("../usergrouplist.csv")
        # XXX This needs to be a Callable that is passed in.

        existing_groups: list[str] = self._get_user_groups()
        all_existing_users: v1UsersMap = self._get_user_list_full()
        all_source_usernames: list[str] = [
            user.username for users in source_users_groups.values() for user in users
        ]

        for source_group_name, source_users in source_users_groups.items():
            logging.info(f"started processing source group '{source_group_name}'")
            # Create group if it doesn't exist
            if source_group_name not in existing_groups:
                self._create_usergroup(source_group_name)

            group_existing_users: v1UsersMap = self._get_users_in_usergroup(
                source_group_name
            )
            group_users_to_add: UserList = []

            for source_user in source_users:
                logging.info(
                    f"started processing of source user {source_user} in group '{source_group_name}'"
                )
                # Create user if not exists
                if source_user.username not in all_existing_users:
                    self._create_user(source_user)
                else:
                    # Enable user if user exists but is disabled
                    if not all_existing_users[source_user.username].active:
                        self._enable_users([source_user])

                if source_user.username not in group_existing_users:
                    group_users_to_add.append(source_user)

                # Link with agent user
                self._link_with_agent_user(source_user)

            # Add users to group
            self._add_users_to_usergroup(source_group_name, group_users_to_add)

            # Disable users existing in this user-group that are not present in the full source
            # users list. This condition checks that they are not apart of any other user-group.
            # Since we are only disabling users who exist and are a part of a source user-group,
            # we will not affect other existing users who are not a member of the source user-group.
            # In other words, we should skip all manually created accounts.
            self._disable_users(
                [
                    user
                    for user in group_existing_users.values()
                    if user.username not in all_source_usernames
                    and user.username == "admin"  # Antifootgun, just in case.
                ]
            )

            logging.info(f"finished processing group {source_group_name}")

        logging.info("finished processing all user groups")

        return

    def _login(self) -> None:
        user = os.environ.get("DET_USER", None)
        password = os.environ.get("DET_PASSWORD", None)
        master = os.environ.get("DET_MASTER", None)
        if user is None or password is None:
            raise ValueError(
                "You must set DET_MASTER, DET_USER and DET_PASSWORD before executing this script"
            )
        client.login(master, user, password)
        self._session = client._determined._session


    def _get_user_groups(self) -> list[str]:
        # XXX raises determined.common.api.errors.BadRequestException if group does not exist
        # XXX Need to handle condition in which response is equal to limit, i.e., is incomplete.
        limit = 500
        body = api.bindings.v1GetGroupsRequest(limit=limit, offset=None, userId=None)
        if self._dry_run:
            return []
        resp = api.bindings.post_GetGroups(self._session, body=body)
        for group_res in resp.groups:
            logging.info(
                f"found existing user-group '{group_res.group.name}' "
                f"with {group_res.numMembers} members"
            )
        return [group.group.name for group in resp.groups]

    def _get_user_list_full(self) -> v1UsersMap:
        users = api.bindings.get_GetUsers(session=self._session).users
        return {user.username: user for user in users}

    def _create_usergroup(self, group_name: str) -> None:
        body = api.bindings.v1CreateGroupRequest(name=group_name, addUsers=None)
        if not self._dry_run:
            api.bindings.post_CreateGroup(self._session, body=body)
        logging.info(f"created user-group '{group_name}'")

    def _get_users_in_usergroup(self, group_name: str) -> v1UsersMap:
        ret = {}
        if self._dry_run:
            return ret
        group_id = cli.user_groups.group_name_to_group_id(self._session, group_name)
        resp = api.bindings.get_GetGroup(self._session, groupId=group_id)
        logging.info(f"retrieved user-group details: {resp.group}")
        for user in resp.group.users:
            ret[user.username] = user
            logging.info(f"found user '{user.username}' in group '{group_name}'")
        return ret

    def _create_user(self, user: User) -> None:
        create_user = api.bindings.v1User(
            username=user.username,
            admin=False,
            active=True,
            remote=True,
        )
        body = api.bindings.v1PostUserRequest(user=create_user)
        if not self._dry_run:
            api.bindings.post_PostUser(self._session, body=body)
        logging.info(f"created user '{user.username}'")

    def _link_with_agent_user(self, user: User) -> None:
        v1agent_user_group = api.bindings.v1AgentUserGroup(
            agentGid=user.gid,
            agentGroup=user.group_name,
            agentUid=user.uid,
            agentUser=user.username,
        )
        if not self._dry_run:
            body = api.bindings.v1PatchUser(agentUserGroup=v1agent_user_group)
            user_ids = cli.user_groups.usernames_to_user_ids(self._session, [user.username])
            api.bindings.patch_PatchUser(self._session, body=body, userId=user_ids[0])
        logging.info(
            f"linked user '{user.username}' with agent user {v1agent_user_group}"
        )

    def _add_users_to_usergroup(self, group_name: str, users: UserList) -> None:
        usernames = [u.username for u in users]
        if not self._dry_run:
            group_id = cli.user_groups.group_name_to_group_id(self._session, group_name)
            user_ids = cli.user_groups.usernames_to_user_ids(self._session, usernames)
            body = api.bindings.v1UpdateGroupRequest(groupId=group_id, addUsers=user_ids)
            api.bindings.put_UpdateGroup(self._session, groupId=group_id, body=body)
        logging.info(f"added users to group '{group_name}', user list: {usernames}")

    def _disable_users(self, users: UserList) -> None:
        usernames = [u.username for u in users]
        if not self._dry_run:
            user_ids = cli.user_groups.usernames_to_user_ids(self._session, usernames)
            body = api.bindings.v1PatchUser(active=False)
        for username in usernames:
            api.bindings.patch_PatchUser(self._session, body=body, userId=user_id)
            logging.info(f"deactivated user '{username}'")

    def _enable_users(self, users: UserList) -> None:
        usernames = [u.username for u in users]
        if not self._dry_run:
            user_ids = cli.user_groups.usernames_to_user_ids(self._session, usernames)
            body = api.bindings.v1PatchUser(active=True)
        for username in usernames:
            api.bindings.patch_PatchUser(self._session, body=body, userId=user_id)
            logging.info(f"activated user '{username}'")


# XXX maybe use a factory
# XXX UserGroups sucks as a name
#   XXX This is really a "Source Users Groups factory"
def parse_userlist_csv(filepath: str) -> UserGroups:
    # XXX probably don't need error handling right now as this might get replaced.
    expected_headers = ["groupname", "username", "uid", "gid"]
    delim = ","

    user_groups = UserGroups()

    with open(filepath, "r") as f:
        for ii, line in enumerate(f.readlines()):
            line = line.rstrip()
            fields = line.split(delim)
            if ii == 0:
                for exp_head in expected_headers:
                    # XXX Doesn't handle duplicate header entries
                    if exp_head not in exp_head:
                        raise ValueError(
                            f"Could not find expected header '{exp_head}' in {fields}"
                        )
                headers = fields
                continue

            group_name = fields[headers.index("groupname")]

            if group_name not in user_groups:
                user_groups[group_name] = UserList()

            user = User(
                fields[headers.index("username")],
                int(fields[headers.index("uid")]),
                int(fields[headers.index("gid")]),
            )

            logging.debug(f"parsed group '{group_name}' with user: {user}")
            user_groups[group_name].append(user)

    return user_groups

def configure_logging(dry_run: bool = True) -> None:
    logging_format="%(asctime)s: %(levelname)s: %(message)s"
    if dry_run:
        logging_format="%(asctime)s: DRYRUN: %(levelname)s: %(message)s"

    logging.basicConfig(format=logging_format, level=logging.INFO)

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("--apply", action="store_true", help="actually apply the changes")
    args = arg_parser.parse_args()

    dry_run = not args.apply

    configure_logging(dry_run)
    user_sync = UserSync(dry_run)

    user_sync.sync_users()
