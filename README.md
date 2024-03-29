# determined-ai-user-sync
Script for creating and synchronizing users in Determined AI with an external user list 

# Detailed usage:
- Simply define a function which produces a SourceGroups object as defined in `det_user_sync/types.py`
- Then the `run_user_sync.py` utility can be run with the function and arguments passed into it.
The structure is this:
```
# my_user_source.py:
from det_user_sync import SourceGroups, SourceUser, SourceUsers


def my_func(arg: any) -> SourceGroups:
    groups = SourceGroups()

    for groupname, source_user_list in ...:
        if groupname not in groups:
            groups[groupname] = SourceUsers()
            
        for source_user in source_user_list:

            user = SourceUser(
                username=...,
                uid=int(...),
                gid=int(...),
                unix_username=...,
                unix_groupname=...,
                display_name=...,
                password=...,
            )

            groups[groupname].append(user)

    return groups
```

The `run_user_sync.py` would then be called like this:
```
$ run_user_sync.py --source_func my_user_source:my_func --func_args ./foo.txt
```
- If no `password` is specified on the `SourceUser` object, the user will be created as a "remote" user


# Example:
The following is provided:
- `user_group_list.csv`: a list of example users
- `csv_user_example.py`: contains the `parse_userlist_csv` example function.

Here is an example run:

```
$ python run_user_sync.py --period-mins 1 --source-func csv_user_example:parse_userlist_csv --func-args ./user_group_list.csv
2024-03-07 13:35:33,073: DRYRUN: INFO: running as service with period of 1 minutes
2024-03-07 13:35:33,073: DRYRUN: INFO: started user sync run
2024-03-07 13:35:33,077: DRYRUN: INFO: logged in as user 'admin' to http://localhost:8080
2024-03-07 13:35:33,080: DRYRUN: INFO: starting call to source groups func
2024-03-07 13:35:33,080: DRYRUN: INFO: ended call to source groups func
2024-03-07 13:35:33,082: DRYRUN: INFO: started processing source group 'admins'
2024-03-07 13:35:33,082: DRYRUN: INFO: created user-group 'admins'
2024-03-07 13:35:33,082: DRYRUN: INFO: started processing of source user SourceUser(username='abowen', uid=100, gid=100, unix_username='abowen', unix_groupname='developers', display_name='Andrew Bowen', password='super_secret') in group 'admins'
2024-03-07 13:35:33,082: DRYRUN: INFO: linked user 'abowen' with agent user v1AgentUserGroup(agentGid=100, agentGroup=developers, agentUid=100, agentUser=abowen)
2024-03-07 13:35:33,082: DRYRUN: INFO: added users to group 'admins', user list: ['abowen']
2024-03-07 13:35:33,082: DRYRUN: INFO: finished processing group admins
2024-03-07 13:35:33,083: DRYRUN: INFO: started processing source group 'groupA'
2024-03-07 13:35:33,083: DRYRUN: INFO: created user-group 'groupA'
2024-03-07 13:35:33,083: DRYRUN: INFO: started processing of source user SourceUser(username='cdavis', uid=102, gid=102, unix_username='cdavis', unix_groupname='developers', display_name='Carl Davis', password=None) in group 'groupA'
2024-03-07 13:35:33,083: DRYRUN: INFO: linked user 'cdavis' with agent user v1AgentUserGroup(agentGid=102, agentGroup=developers, agentUid=102, agentUser=cdavis)
2024-03-07 13:35:33,083: DRYRUN: INFO: started processing of source user SourceUser(username='efeynman', uid=103, gid=103, unix_username='efeynman', unix_groupname='admins', display_name='Eric Feynman', password=None) in group 'groupA'
2024-03-07 13:35:33,083: DRYRUN: INFO: linked user 'efeynman' with agent user v1AgentUserGroup(agentGid=103, agentGroup=admins, agentUid=103, agentUser=efeynman)
2024-03-07 13:35:33,083: DRYRUN: INFO: added users to group 'groupA', user list: ['cdavis', 'efeynman']
2024-03-07 13:35:33,083: DRYRUN: INFO: finished processing group groupA
2024-03-07 13:35:33,083: DRYRUN: INFO: started processing source group 'groupB'
2024-03-07 13:35:33,083: DRYRUN: INFO: created user-group 'groupB'
2024-03-07 13:35:33,083: DRYRUN: INFO: started processing of source user SourceUser(username='gharris', uid=103, gid=103, unix_username='gharris', unix_groupname='admins', display_name='Greg Harris', password=None) in group 'groupB'
2024-03-07 13:35:33,083: DRYRUN: INFO: linked user 'gharris' with agent user v1AgentUserGroup(agentGid=103, agentGroup=admins, agentUid=103, agentUser=gharris)
2024-03-07 13:35:33,083: DRYRUN: INFO: started processing of source user SourceUser(username='ijoplin', uid=104, gid=104, unix_username='ijoplin', unix_groupname='developers', display_name='Ingrid Joplin', password=None) in group 'groupB'
2024-03-07 13:35:33,083: DRYRUN: INFO: linked user 'ijoplin' with agent user v1AgentUserGroup(agentGid=104, agentGroup=developers, agentUid=104, agentUser=ijoplin)
2024-03-07 13:35:33,083: DRYRUN: INFO: added users to group 'groupB', user list: ['gharris', 'ijoplin']
2024-03-07 13:35:33,083: DRYRUN: INFO: finished processing group groupB
2024-03-07 13:35:33,083: DRYRUN: INFO: finished processing all user groups
2024-03-07 13:35:33,083: DRYRUN: INFO: ended user sync run

```
