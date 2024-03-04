# determined-ai-user-sync
Script for creating and synchronizing users in Determined AI with an external user list 

# Detailed usage:
- Simply define a function which produces a SourceGroups object as defined in `det_user_sync/types.py`
- Then the run_user_sync.py can be run and that function along with it's arguments can be passed in. 

# Example:
The following is provided:
- `user_group_list.csv`: a list of example users
- `csv_user_example.py`: contains the `parse_userlist_csv` example function.

Here is an example run:

```
$ python run_user_sync.py  --source_func csv_user_example:parse_userlist_csv --func_args ./user_group_list.csv 
2024-03-04 12:18:31,496: DRYRUN: INFO: started processing source group 'groupA'
2024-03-04 12:18:31,496: DRYRUN: INFO: created user-group 'groupA'
2024-03-04 12:18:31,496: DRYRUN: INFO: started processing of source user SourceUser(username='abowen', uid=100, gid=100, group_name='Unknown') in group 'groupA'
2024-03-04 12:18:31,496: DRYRUN: INFO: created user 'abowen'
2024-03-04 12:18:31,496: DRYRUN: INFO: linked user 'abowen' with agent user v1AgentUserGroup(agentGid=100, agentGroup=Unknown, agentUid=100, agentUser=abowen)
2024-03-04 12:18:31,497: DRYRUN: INFO: started processing of source user SourceUser(username='cdavis', uid=102, gid=102, group_name='Unknown') in group 'groupA'
2024-03-04 12:18:31,497: DRYRUN: INFO: created user 'cdavis'
2024-03-04 12:18:31,497: DRYRUN: INFO: linked user 'cdavis' with agent user v1AgentUserGroup(agentGid=102, agentGroup=Unknown, agentUid=102, agentUser=cdavis)
2024-03-04 12:18:31,497: DRYRUN: INFO: started processing of source user SourceUser(username='efeynman', uid=103, gid=103, group_name='Unknown') in group 'groupA'
2024-03-04 12:18:31,497: DRYRUN: INFO: created user 'efeynman'
2024-03-04 12:18:31,497: DRYRUN: INFO: linked user 'efeynman' with agent user v1AgentUserGroup(agentGid=103, agentGroup=Unknown, agentUid=103, agentUser=efeynman)
2024-03-04 12:18:31,497: DRYRUN: INFO: added users to group 'groupA', user list: ['abowen', 'cdavis', 'efeynman']
2024-03-04 12:18:31,497: DRYRUN: INFO: finished processing group groupA
2024-03-04 12:18:31,497: DRYRUN: INFO: started processing source group 'groupB'
2024-03-04 12:18:31,497: DRYRUN: INFO: created user-group 'groupB'
2024-03-04 12:18:31,497: DRYRUN: INFO: started processing of source user SourceUser(username='gharris', uid=103, gid=103, group_name='Unknown') in group 'groupB'
2024-03-04 12:18:31,497: DRYRUN: INFO: created user 'gharris'
2024-03-04 12:18:31,497: DRYRUN: INFO: linked user 'gharris' with agent user v1AgentUserGroup(agentGid=103, agentGroup=Unknown, agentUid=103, agentUser=gharris)
2024-03-04 12:18:31,497: DRYRUN: INFO: started processing of source user SourceUser(username='ijoplin', uid=104, gid=104, group_name='Unknown') in group 'groupB'
2024-03-04 12:18:31,497: DRYRUN: INFO: created user 'ijoplin'
2024-03-04 12:18:31,497: DRYRUN: INFO: linked user 'ijoplin' with agent user v1AgentUserGroup(agentGid=104, agentGroup=Unknown, agentUid=104, agentUser=ijoplin)
2024-03-04 12:18:31,497: DRYRUN: INFO: added users to group 'groupB', user list: ['gharris', 'ijoplin']
2024-03-04 12:18:31,497: DRYRUN: INFO: finished processing group groupB
2024-03-04 12:18:31,497: DRYRUN: INFO: finished processing all user groups
```
