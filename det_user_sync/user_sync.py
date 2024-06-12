#!/usr/bin/env python3
import dataclasses
import logging
import os
import json
import traceback
from collections.abc import Callable
from typing import Any, Optional

from determined import cli
from determined.common import api
from determined.experimental import client

from .types import SourceGroups, SourceUser, SourceUsers, v1UsersMap


# XXX Need to test try/catch/finally report generation from random in middle of execution.


class UserSyncReport:
    def __init__(self) -> None:
        NameList = list[str]
        self._created_groups: NameList = []
        self._created_users: NameList = []
        self._enabled_users: NameList = []
        self._added_group_users: dict[str, NameList] = {}
        self._removed_group_users: dict[str, NameList] = {}
        self._disabled_users: NameList = []
        self._report_items: list[dict[str, Any]] = []

    def created_group(self, groupname: str) -> None:
        self._created_groups.append(groupname)

    def created_user(self, username: str) -> None:
        self._created_users.append(username)

    def enabled_user(self, username: str) -> None:
        self._enabled_users.append(username)

    def removed_group_user(self, groupname: str, username: str) -> None:
        if not self._removed_group_users.get(groupname):
            self._removed_group_users[groupname] = []    
        self._removed_group_users[groupname].append(username)

    def added_group_user(self, groupname: str, username: str) -> None:
        if not self._added_group_users.get(groupname):
            self._added_group_users[groupname] = []    
        self._added_group_users[groupname].append(username)

    def disabled_user(self, username: str) -> None:
        self._disable_users.append(username)

    def __repr__(self) -> str:
        self._hydrate_report_items()
        return "\n".join(str(r) for r in self._report_items)

    def log(self) -> None:
        self._hydrate_report_items()
        for item in self._report_items:
            logging.info("REPORT: {}".format(
                ", ".join(f"{k}={v}" for k, v in item.items())
            ))

    def to_json(self) -> str:
        self._hydrate_report_items()
        return json.dumps(self._report_items)

    def _hydrate_report_items(self) -> None:
        self._report_items = []
        
        self._report_items.append({
            "action": "created_users",
            "usercount": len(self._created_users),
            "usernames": self._created_users
        })

        for groupname, usernames in self._added_group_users.items():
            self._report_items.append({
                "action": "added_users_to_group",
                "groupname": groupname,
                "usercount": len(usernames),
                "usernames": usernames
            })

        for groupname, usernames in self._removed_group_users.items():
            self._report_items.append({
                "action": "removed_users_from_group",
                "groupname": groupname,
                "usercount": len(usernames),
                "usernames": usernames
            })

        self._report_items.append({
            "action": "disabled_users",
            "usercount": len(self._disabled_users),
            "usernames": self._disabled_users
        })

        self._report_items.append({
            "action": "summary",
            "total_users_created": len(self._created_users),
            "total_users_added_to_groups": len(tuple(u for u in self._added_group_users.values())),
            "total_users_removed_from_groups": len(tuple(u for u in self._removed_group_users.values())),
            "total_users_disabled": len(self._disabled_users),
        })

class UserSync:
    def __init__(
        self,
        source_groups_func: Callable[[Any], SourceGroups],
        source_groups_func_args: Optional[list[Any]],
        dry_run: bool = True,
    ) -> UserSyncReport:
        self._session: api.Session = None
        self._dry_run = dry_run
        self._source_groups_func = source_groups_func
        self._source_groups_func_args = source_groups_func_args
        self._report = UserSyncReport()

    def sync_users(self) -> None:
        # Make sure we have an active session
        if self._session is None:
            self._login()

        try:
            _ = self._whoami()
        except api.errors.UnauthenticatedException:
            logging.info("session expired")
            self._login()

        # Get source groups and users
        logging.info("starting call to source groups func")
        # TODO: see if we can async and timeout call this function
        try:
            source_groups_users = self._source_groups_func(
                self._source_groups_func_args
            )
        except Exception as e:
            exc_str = "".join(traceback.format_tb(e.__traceback__))
            logging.error(f"unable to fetch source groups, exception: \n{exc_str}{e}")
            return

        total_users = sum([len(u) for u in source_groups_users.values()])
        logging.info(
            f"found {len(source_groups_users)} groups with total users: {total_users}"
        )
        logging.info("ended call to source groups func")

        # Get existing groups and users
        try:
            existing_groups: list[str] = self._get_user_groups()
            all_existing_users: v1UsersMap = self._get_user_list_full()
        except Exception as e:
            logging.error(f"unable to get user list, exception {e}")
            return

        all_source_usernames: list[str] = [
            user.username for users in source_groups_users.values() for user in users
        ]

        for source_group_name, source_users in source_groups_users.items():
            logging.info(f"started processing source group '{source_group_name}'")
            # Create group if it doesn't exist
            if source_group_name not in existing_groups:
                try:
                    self._create_usergroup(source_group_name)
                except Exception as e:
                    logging.error(
                        f"unable to create group '{source_group_name}', exception: {e}"
                    )
                    logging.info(f"skipping source group '{source_group_name}'")
                    continue

            try:
                existing_group_users: v1UsersMap = self._get_users_in_usergroup(
                    source_group_name
                )
                
            except Exception as e:
                logging.error(
                    f"unable to get group members '{source_group_name}', exception: {e}"
                )
                logging.info(f"skipping source group '{source_group_name}'")
                continue

            group_users_to_add: SourceUsers = []

            for source_user in source_users:
                logging.info(
                    f"started processing of source user {source_user}"
                    f"in group '{source_group_name}'"
                )
                # XXX create a __repr__ method for source_user which masks the password
                # Create user if not exists
                if source_user.username not in all_existing_users:
                    try:
                        # XXX I think it is fine if we don't update all_existing_users on dryrun
                        # because we only use this to determine if the user is active or not.
                        user = self._create_user(source_user)
                        if user is not None:
                            all_existing_users[source_user.username] = user
                    except Exception as e:
                        logging.error(
                            f"unable to create user '{source_user.username}', exception: {e}"
                        )
                        logging.info(f"skipping source user '{source_user.username}'")
                        continue
                else:
                    # Enable user if user exists but is disabled
                    if not all_existing_users[source_user.username].active:
                        try:
                            self._enable_users([source_user])
                        except Exception as e:
                            logging.error(
                                "unable to enable disabled user "
                                f"'{source_user.username}', exception: {e}"
                            )

                if source_user.username not in existing_group_users:
                    group_users_to_add.append(source_user)

                # Link with agent user
                try:
                    self._link_with_agent_user(source_user)
                except Exception as e:
                    logging.error(
                        f"unable to link with agent user '{source_user.username}', exception: {e}"
                    )

            # Add users to group
            try:
                self._add_users_to_usergroup(source_group_name, group_users_to_add)
            except Exception as e:
                logging.error(
                    f"unable to add users to user-group '{source_group_name}', "
                    f"userlist: {group_users_to_add}, exception: {e}"
                )

            # Remove users from group
            group_users_to_remove: v1UsersMap = {}
            for existing_username, existing_user in existing_group_users.items():
                if existing_username not in [su.username for su in source_users]:
                    group_users_to_remove[existing_username] = existing_user
            self._remove_users_from_usergroup(source_group_name, group_users_to_remove)

            # Disable users existing in this user-group that are not present in the full source
            # users list. This condition checks that they are not apart of any other user-group.
            # Since we are only disabling users who exist and are a part of a source user-group,
            # we will not affect other existing users who are not a member of the source user-group.
            # In other words, we should skip all manually created accounts.
            users_to_disable = []
            for user in existing_group_users.values():
                if (
                    user.username not in all_source_usernames
                    and user.username != "admin"
                ):
                    users_to_disable.append(user)

            try:
                self._disable_users(users_to_disable)
            except Exception as e:
                logging.error(
                    f"unable to disable users in user-group '{source_group_name}', "
                    f"userlist: {users_to_disable}, exception: {e}"
                )

            # XXX think about creating exceptions that break out of the loop
            # and log differently here.
            # I.e., make it clear we processed a group but with errors.
            logging.info(f"finished processing group {source_group_name}")
        logging.info("finished processing all user groups")

        return self._report

    def _whoami(self) -> str:
        resp = api.bindings.get_GetMe(self._session)
        return str(resp.user.username)

    def _login(self) -> None:
        user = os.environ.get("DET_USER", None)
        password = os.environ.get("DET_PASSWORD", None)
        master = os.environ.get("DET_MASTER", None)
        if user is None or password is None:
            raise ValueError(
                "You must set DET_MASTER, DET_USER and DET_PASSWORD before executing this script"
            )
        noverify = True
        det = client.Determined(master, user, password, None, None, noverify)
        logging.info(f"logged in as user '{user}' to {master}")
        self._session = det._session

    # XXX Wrappers for legacy function locations
    def _group_name_to_group_id(self, group_name: str) -> int:
        try:
            # XXX Legacy
            return cli.user_groups.group_name_to_group_id(self._session, group_name)
        except AttributeError:
            return api.group_name_to_group_id(self._session, group_name)

    def _usernames_to_user_ids(self, usernames: list[str]) -> list[int]:
        try:
            # XXX legacy
            return cli.user_groups.usernames_to_user_ids(self._session, usernames)
        except AttributeError:
            return api.usernames_to_user_ids(self._session, usernames)

    def _get_user_groups(self) -> list[str]:
        # XXX raises determined.common.api.errors.BadRequestException if group does not exist
        # XXX Need to handle condition in which response is equal to limit, i.e., is incomplete.
        limit = 500
        body = api.bindings.v1GetGroupsRequest(limit=limit, offset=None, userId=None)
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
        self._report.created_group(group_name)
        logging.info(f"created user-group '{group_name}'")

    def _get_users_in_usergroup(self, group_name: str) -> v1UsersMap:
        ret: v1UsersMap = {}
        try:
            group_id = self._group_name_to_group_id(group_name)
        except api.errors.BadRequestException:
            # BadRequestException: 'could not find user group name ...'
            if self._dry_run:
                # Occurs when it is a dry run and so we didn't create the group.
                return ret
            raise

        resp = api.bindings.get_GetGroup(self._session, groupId=group_id)

        logging.info(f"retrieved user-group details: {resp.group}")
        for user in resp.group.users:
            ret[user.username] = user
            logging.info(f"found user '{user.username}' in group '{group_name}'")
        return ret

    def _create_user(self, user: SourceUser) -> api.bindings.v1User:
        remote = True
        hashed_password = None
        if user.password is not None and user.password != "":
            hashed_password = api.salt_and_hash(user.password)
            remote = False

        create_user = api.bindings.v1User(
            username=user.username,
            admin=False,
            active=True,
            remote=remote,
            displayName=user.display_name,
        )
        body = api.bindings.v1PostUserRequest(
            user=create_user, password=hashed_password, isHashed=True
        )
        if not self._dry_run:
            self._report.created_user(user.username)
            logging.info(f"created user '{user.username}': {create_user}")
            resp = api.bindings.post_PostUser(self._session, body=body)
            return resp.user
        self._report.created_user(user.username)
        logging.info(f"created user '{user.username}': {create_user}")

    def _link_with_agent_user(self, user: SourceUser) -> None:
        v1agent_user_group = api.bindings.v1AgentUserGroup(
            agentGid=user.gid,
            agentGroup=user.unix_groupname,
            agentUid=user.uid,
            agentUser=user.unix_username,
        )
        if not self._dry_run:
            body = api.bindings.v1PatchUser(agentUserGroup=v1agent_user_group)
            user_ids = self._usernames_to_user_ids([user.username])
            api.bindings.patch_PatchUser(self._session, body=body, userId=user_ids[0])
        logging.info(
            f"linked user '{user.username}' with agent user {v1agent_user_group}"
        )

    def _add_users_to_usergroup(self, group_name: str, users: SourceUsers) -> None:
        usernames = [u.username for u in users]
        if not self._dry_run:
            group_id = self._group_name_to_group_id(group_name)
            user_ids = self._usernames_to_user_ids(usernames)
            body = api.bindings.v1UpdateGroupRequest(
                groupId=group_id, addUsers=user_ids
            )
            api.bindings.put_UpdateGroup(self._session, groupId=group_id, body=body)
        for username in usernames:
            self._report.added_group_user(group_name, username)
        logging.info(f"added users to group '{group_name}', user list: {usernames}")

    def _remove_users_from_usergroup(self, group_name: str, users: v1UsersMap) -> None:
        # XXX This needs to be in a try / catch / finally
        # I need to append to a list of disabled users as we disable them.
        if len(users) == 0:
            return
        usernames = list(users.keys())
        group_id = self._group_name_to_group_id(group_name)
        user_ids = self._usernames_to_user_ids(usernames)

        body = api.bindings.v1UpdateGroupRequest(groupId=group_id, removeUsers=user_ids)
        if not self._dry_run:
            api.bindings.put_UpdateGroup(self._session, groupId=group_id, body=body)
        for username in usernames:
            self._report.removed_group_user(group_name, username)
        logging.info(f"removed {len(usernames)} users from group '{group_name}', user list: {usernames}")

    def _disable_users(self, users: SourceUsers) -> None:
        # XXX This needs to be in a try / catch / finally
        # I need to append to a list of disabled users as we disable them.
        usernames = [u.username for u in users]
        if not self._dry_run:
            user_ids = self._usernames_to_user_ids(usernames)
            body = api.bindings.v1PatchUser(active=False)
            for ii, username in enumerate(usernames):
                api.bindings.patch_PatchUser(
                    self._session, body=body, userId=user_ids[ii]
                )
                logging.info(f"deactivated user '{username}'")
                self._report.disabled_user(username)
            logging.info(f"deactived a total of {len(usernames)} users")
            return
        for username in usernames:
            logging.info(f"deactivated user '{username}'")
            self._report.disabled_user(username)
        logging.info(f"deactived a total of {len(usernames)} users")

    def _enable_users(self, users: SourceUsers) -> None:
        usernames = [u.username for u in users]
        if not self._dry_run:
            user_ids = self._usernames_to_user_ids(usernames)
            body = api.bindings.v1PatchUser(active=True)
            for ii, username in enumerate(usernames):
                api.bindings.patch_PatchUser(
                    self._session, body=body, userId=user_ids[ii]
                )
                self._report.enabled_user(username)
                logging.info(f"activated user '{username}'")
            return
        for username in usernames:
            self._report.enabled_user(username)
            logging.info(f"activated user '{username}'")
