
# Find all agents including NodeAgents
recipeQueryAllAgentsAndNodeAgents=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE (C.COMPONENT_TYPE='agent' OR C.COMPONENT_TYPE='node') \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# UserAdminAgent Query
recipeQueryUserAdminAgent=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME like 'UserAdminAgent%'

################################################################################################################
# NAI queries
################################################################################################################

################################################################################################################
# BEGIN M&R security manager queries
################################################################################################################

# Find all agents that are SecurityMnRManagers
# Use this when adding AdaptivityEngine stuff for security thread
# Can also use this for components that go in every such Agent
recipeQuerySecurityMnRAgents=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID like \
                               '%SecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find all agents that are SecurityMnRManagers for an Enclave
# Use this when adding AdaptivityFilter stuff for security thread
# Can also use this for components that go in every such Agent
recipeQueryEnclaveSecurityMnRAgents=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID like \
                               'Enclave%SecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the Enclave1SecurityManager agent
# Use this when adding AdaptivityFilter stuff for security thread
# Can also use this for components that go in every such Agent
recipeQueryEnclave1SecurityMnRAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'Enclave1SecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the Enclave2SecurityManager agent
# Use this when adding AdaptivityFilter stuff for security thread
# Can also use this for components that go in every such Agent
recipeQueryEnclave2SecurityMnRAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'Enclave2SecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the Enclave3SecurityManager agent
# Use this when adding AdaptivityFilter stuff for security thread
# Can also use this for components that go in every such Agent
recipeQueryEnclave3SecurityMnRAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'Enclave3SecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the Enclave4SecurityManager agent
# Use this when adding AdaptivityFilter stuff for security thread
# Can also use this for components that go in every such Agent
recipeQueryEnclave4SecurityMnRAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'Enclave4SecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:


# Get all Agents that are _not_ SecurityMnRAgents. IE, those that are managed
recipeQueryNOTSecurityMnRAgents=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE (C.COMPONENT_TYPE='agent' OR C.COMPONENT_TYPE='node') AND C.COMPONENT_ALIB_ID not like \
                               '%SecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Get the Society Security Manager agent
#This is for LoginFailureSensor stuff
#this one is for BootStrapEventPlugin0.sql
recipeQuerySocietySecurityMnRAgent=\
SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'SocietySecurityMnRManager' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

################################################################################################################
# END M&R security manager queries
################################################################################################################

################################################################################################################
# BEGIN Policy Domain Manager queries
################################################################################################################
# Find all agents that are DomainManager
recipeQueryDomainManagerAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND \
    (C.COMPONENT_ALIB_ID like '%PolicyDomainManager%Agent' AND C.COMPONENT_ALIB_ID not like '%PolicyDomainManager%ServletAgent') \
     AND \
    (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find all agents that are DomainManager Servlet Agents
recipeQueryDomainManagerServletAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND \
    C.COMPONENT_ALIB_ID like '%PolicyDomainManager%ServletAgent' \
     AND \
    (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

################################################################################################################

# Find the PolicyDomainManager1 agent
recipeQueryPolicyDomainManager1Agent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager1' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the PolicyDomainManager2 agent
recipeQueryPolicyDomainManager2Agent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager2' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the PolicyDomainManager3 agent
recipeQueryPolicyDomainManager3Agent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager3' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the PolicyDomainManager4 agent
recipeQueryPolicyDomainManager4Agent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager4' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

################################################################################################################

# Find the PolicyDomainManager1Servlet agent
recipeQueryPolicyDomainManager1ServletAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager1ServletAgent' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the PolicyDomainManager2Servlet agent
recipeQueryPolicyDomainManager2ServletAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager2ServletAgent' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the PolicyDomainManager3Servlet agent
recipeQueryPolicyDomainManager3ServletAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager3ServletAgent' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

# Find the PolicyDomainManager4Servlet agent
recipeQueryPolicyDomainManager4ServletAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID = \
                               'PolicyDomainManager4ServletAgent' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match:

################################################################################################################
# END Policy Domain Manager queries
################################################################################################################

recipeQueryRoverAgent=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME='TestRover'

recipeQueryRoverControllerAgent=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME='TestRoverController'

# Select the University of Memphis Manager
recipeQueryForUMmrmangerAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM ALIB_COMPONENT C, ASB_COMPONENT_HIERARCHY H \
  WHERE C.COMPONENT_TYPE='agent' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match: \
    AND C.COMPONENT_NAME = 'UMmrmanager'

# Find TestSensor agent (this agent is not needed except for testing)
recipeQueryForTestSensorAgent=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM ALIB_COMPONENT C, ASB_COMPONENT_HIERARCHY H \
  WHERE C.COMPONENT_TYPE='agent' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match: \
    AND C.COMPONENT_NAME = 'TestSensorAgent'

# AGG-Agent query and NOT AGG-agent Query
# The society security manager and the enclave security managers are also agg-agents
recipeQueryAGGAgent=\
  SELECT C.COMPONENT_ALIB_ID \
  FROM alib_component C, asb_component_hierarchy H \
  WHERE (C.COMPONENT_TYPE='agent' AND C.COMPONENT_ALIB_ID like '%SecurityMnRManager' \
          AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
          AND H.ASSEMBLY_ID :assembly_match:) \
         OR ( COMPONENT_TYPE = 'agent' AND COMPONENT_NAME='AGG-Agent' ) \
         OR ( COMPONENT_TYPE = 'agent' AND COMPONENT_NAME='SCmrmanager' )

#recipeQueryAGGAgent=\
# SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME='AGG-Agent'

# Both "Agg-agent" and the UofM manager are aggregators
# The old query was excluding the security managers. However, they also have sensors, so they need to be
# queried.
#   AND COMPONENT_NAME NOT LIKE '%SecurityMnRManager'
recipeQueryNotAGGAgent=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT WHERE (COMPONENT_TYPE = 'agent' OR COMPONENT_TYPE = 'node') AND \
   COMPONENT_NAME NOT IN ('AGG-Agent', 'UMmrmanager') 

# All Node Agents that are members of Enclave1Security-COMM
recipeQueryEnclave1SecurityCommunityNodeAgents=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT, COMMUNITY_ENTITY_ATTRIBUTE WHERE COMPONENT_TYPE = 'node' AND \
   COMPONENT_NAME = ENTITY_ID and COMMUNITY_ID = 'Enclave1Security-COMM'

# All Node Agents that are members of Enclave2Security-COMM
recipeQueryEnclave2SecurityCommunityNodeAgents=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT, COMMUNITY_ENTITY_ATTRIBUTE WHERE COMPONENT_TYPE = 'node' AND \
   COMPONENT_NAME = ENTITY_ID and COMMUNITY_ID = 'Enclave2Security-COMM'

# All Node Agents that are members of Enclave3Security-COMM
recipeQueryEnclave3SecurityCommunityNodeAgents=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT, COMMUNITY_ENTITY_ATTRIBUTE WHERE COMPONENT_TYPE = 'node' AND \
   COMPONENT_NAME = ENTITY_ID and COMMUNITY_ID = 'Enclave3Security-COMM'

# All Node Agents that are members of Enclave4Security-COMM
recipeQueryEnclave4SecurityCommunityNodeAgents=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT, COMMUNITY_ENTITY_ATTRIBUTE WHERE COMPONENT_TYPE = 'node' AND \
   COMPONENT_NAME = ENTITY_ID and COMMUNITY_ID = 'Enclave4Security-COMM'

# All SPECIFIC Node Agents that are members of Enclave0 for now belong to Security-Mgmt-COMM
recipeQueryEnclave0SecurityCommunityNodeAgents=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT WHERE COMPONENT_TYPE = 'node' AND \
   COMPONENT_NAME IN ('SOCIETY-SECURITY','USERADMIN-NODE') 

# All ManagementAgents 
recipeQueryManagementAgent=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME LIKE '%RobustnessManager'

# All Enclave1ManagementAgents 
recipeQueryEnclave1ManagementAgent=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME LIKE '%Enclave1SecurityRobustnessManager'

# All Enclave2ManagementAgents 
recipeQueryEnclave2ManagementAgent=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME LIKE '%Enclave2SecurityRobustnessManager'


###############################
## Recipe queries to add the NAI Security Components to the NodeAgents
# (NAISecurityComponents-export.sql)
# Each query finds the Nodes that belong to the named community
# of type 'Security'
# By modifying the name of the community, the role that this member is
# playing, and whether you look for items of type 'node' or of
# type 'agent' or both, you can vary these queries
# to find arbitrary Agents and/or Nodes by their community
# membership. Note that you must have created your communities before
# doing a final save of your experiment.


recipeQuerySecurityEnclave1NodeAgents=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
 WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
     ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'node' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'Member' \
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'Security' \
    AND CA.COMMUNITY_ID = 'Enclave1Security-COMM' 

recipeQuerySecurityEnclave2NodeAgents=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
 WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
     ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'node' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'Member' \
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'Security' \
    AND CA.COMMUNITY_ID = 'Enclave2Security-COMM' 

recipeQuerySecurityEnclave3NodeAgents=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
 WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
     ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'node' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'Member' \
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'Security' \
    AND CA.COMMUNITY_ID = 'Enclave3Security-COMM' 

recipeQuerySecurityEnclave4NodeAgents=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
 WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
     ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'node' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'Member' \
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'Security' \
    AND CA.COMMUNITY_ID = 'Enclave4Security-COMM' 

# Below version would work if COMM ASB was in assembly_match, which it
# is not. See bug #1956
#recipeQuerySecurityEnclave1NodeAgents=\
#SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
#   alib_component AC, \
#   community_attribute CA, \
#   community_entity_attribute CEA, \
#   asb_component_hierarchy ACH \
# WHERE \
#    ACH.ASSEMBLY_ID :assembly_match: \
#    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
#     ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
#    AND AC.COMPONENT_TYPE = 'node' \
#    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
#    AND CEA.ASSEMBLY_ID :assembly_match: \
#    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
#    AND CA.ASSEMBLY_ID :assembly_match: \
#    AND CA.ATTRIBUTE_ID = 'CommunityType' \
#    AND CA.ATTRIBUTE_VALUE = 'Security' \
#    AND CA.COMMUNITY_ID = 'Enclave-1' \
#    AND CEA.ATTRIBUTE_ID = 'Role' \
#    AND CEA.ATTRIBUTE_VALUE = 'Member' 


################################################################################################################
# BEGIN Telcordia queries
################################################################################################################

################
# For Telcordia. Find the Agents which are the Security Enclave
# SecurityManagers. Do not grab the society-wide security manager
# So for the 4 enclave set-up, it should get 4 Agents.
# Used to add the 3 Adaptive Filter Plugins to each of those agents.
# See recipe export AdaptiveFilterPlugins-export.sql
#
# Notes: This assumes (as does the recipe) that Security Manager
# Agents have Role=SecurityManager
# If this role name is not correct, edit it here, and in 
# the recipe (parameter for the TranslatorPlugin)
# Also, this assumes that the society-wide security community
# (as opposed to the enclave communities) has a name that starts
# with "Society". If this is not true, edit the last
# line in this query.
recipeQuerySecurityEnclaveManagerAgents=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
 WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
     ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'agent' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE like 'SecurityManager%' \
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'Security' \
    AND CA.COMMUNITY_ID not like 'Society%'

################################################################################################################
# END Telcordia queries
################################################################################################################

# All Not ManagementAgents 
recipeQueryNotManagementAgent=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME NOT LIKE '%RobustnessManager'

# Query the PlanLogAgent agent.  This is specific to the PSU Castallen sensors.
recipeQueryPlanLogServerAgent=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME='PlanLogAgent'

# Query ht Scalability Managers
recipeQueryAllScalabilityManagers=\
 SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME LIKE '%ScalabilityManager'

######ART did this one haha 
# All Not ManagerAgents 
recipeQueryNotManagerAgents=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME NOT LIKE '%Manager%' \
 and COMPONENT_NAME NOT LIKE '%Agent%'


###########################################
# OPlan Detector Recipe Insertions 
#
# David Dixon-Peugh 6/27/2002
###########################################

recipeQuery20Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 20

recipeQuery19Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 19

          
recipeQuery18Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 18

          
recipeQuery17Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 17

          
recipeQuery16Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 16

          
recipeQuery15Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 15

          

recipeQuery14Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 14

          

recipeQuery13Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 13

          

recipeQuery12Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 12
          

recipeQuery11Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 11

recipeQuery10Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 10

recipeQuery09Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 9

          
recipeQuery08Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 8

          
recipeQuery07Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 7

          
recipeQuery06Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 6

          
recipeQuery05Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 5

          

recipeQuery04Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 4

          

recipeQuery03Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 3

          

recipeQuery02Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 2
          

recipeQuery01Subs=\
  SELECT C1.COMPONENT_ALIB_ID \
    FROM alib_component C1, \
         alib_component C2, \
         asb_agent_relation H \
    WHERE C1.COMPONENT_TYPE='agent' \
      AND C2.COMPONENT_TYPE='agent' \
      AND H.ROLE = 'Subordinate' \
      AND H.SUPPORTED_COMPONENT_ALIB_ID = C1.COMPONENT_ALIB_ID \
      AND H.SUPPORTING_COMPONENT_ALIB_ID = C2.COMPONENT_ALIB_ID \
      AND H.ASSEMBLY_ID :assembly_match: \
    GROUP BY C1.COMPONENT_ALIB_ID \
    HAVING COUNT(*) = 1

recipeQuery00Subs_TINY=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME in ('OSC', 'HNS', '123-MSB', '1-35-ARBN', '47-FSB', '1-6-INFBN', '592-ORDCO', '102-POL-SUPPLYCO', '227-SUPPLYCO', '106-TCBN', '565-RPRPTCO', '191-ORDBN', '343-SUPPLYCO', '110-POL-SUPPLYCO', 'AWR-2', 'TheaterGround', 'CONUSGround', 'ShipPacker', 'PlanePacker', 'DLAHQ', '28-TCBN')

recipeQuery00Subs_FULL=\
SELECT COMPONENT_ALIB_ID \
  FROM alib_component \
WHERE COMPONENT_TYPE = 'agent' \
  AND COMPONENT_NAME in \
('5-MAINTCO', 		'574-SSCO',		'512-MAINTCO', \
 '343-SUPPLYCO',	'18-PERISH-SUBPLT',	'24-ORDCO', \
 '720-EODDET',		'23-ORDCO',		'702-EODDET', \
 '416-POL-TRKCO',	'110-POL-SUPPLYCO',     '632-MAINTCO', \
 '68-MDM-TRKCO',	'66-MDM-TRKCO',		'109-MDM-TRKCO', \
 'AWR-2',		'RSA',			'200-MMC', \
 '7-TCGP-TPTDD',	'286-ADA-SCCO',		'205-MIBDE', \
 '22-SIGBDE',		'12-AVNBDE',		'11-AVN-RGT', \
 '30-MEDBDE',		'DLAHQ',		'OSC', \
 'FORSCOM',		'HNS',			'JSRCMDSE', \
 'ShipPacker',		'CONUSGround',		'TheaterGround', \
 'PlanePacker',		'18-MPBDE',		'52-ENGBN-CBTHVY', \
 '244-ENGBN-CBTHVY',	'2-4-FABN-MLRS',	'3-13-FABN-155', \
 '1-27-FABN',		'900-POL-SUPPLYCO', 	'515-POL-TRKCO', \
 '452-ORDCO',		'529-ORDCO',		'41-POL-TRKCO',	 \
 '51-MDM-TRKCO',	'377-HVY-TRKCO',	'317-MAINTCO', \
 '240-SSCO',		'71-ORDCO',		'565-RPRPTCO', \
 '597-MAINTCO',		'588-MAINTCO',		'27-TCBN-MVTCTRL', \
 '208-SCCO',		'19-MMC',		'592-ORDCO', \
 '26-SSCO',		'596-MAINTCO',		'102-POL-SUPPLYCO', \
 '263-FLDSVC-CO',	'77-MAINTCO',		'594-MDM-TRKCO', \
 '372-CGO-TRANSCO',	'238-POL-TRKCO',	'15-PLS-TRKCO', \
 '2-70-ARBN',		'1-41-INFBN',		'4-1-FABN', \
 '1-13-ARBN',		'70-ENGBN',		'125-FSB', \
 '1-1-CAVSQDN',		'1-501-AVNBN',		'127-DASB', \
 '1-6-INFBN',		'2-6-INFBN',		'1-35-ARBN', \
 '4-27-FABN',		'40-ENGBN', 		'47-FSB', \
 '1-94-FABN',		'25-FABTRY-TGTACQ',	'2-3-FABN', \
 '501-FSB',		'2-37-ARBN',		'16-ENGBN', \
 '1-36-INFBN',		'1-37-ARBN',		'123-MSB', \
 '69-CHEMCO',		'501-MPCO',		'141-SIGBN', \
 '1-4-ADABN',		'501-MIBN-CEWI',	'2-501-AVNBN', \
 '584-MAINTCO',		'541-POL-TRKCO',	'227-SUPPLYCO', \
 '226-MAINTCO' ) 

###########################################
# End OPlan Detector Queries
###########################################

#######################################
# turn on inventory logging at ARBN's and major supply points
#######################################

recipeQueryARBNandMajorInventoryLogging=\
SELECT COMPONENT_ALIB_ID \
  FROM alib_component \
WHERE COMPONENT_TYPE = 'agent' \
  AND COMPONENT_NAME in \
('1-35-ARBN','1-37-ARBN','2-37-ARBN','2-70-ARBN','1-13-ARBN', \
'1-501-AVNBN','501-FSB','47-FSB','125-FSB','127-DASB','123-MSB', \
'343-SUPPLYCO','18-PERISH-SUBPLT','227-SUPPLYCO', \
'191-ORDBN','592-ORDCO','102-POL-SUPPLYCO','110-POL-SUPPLYCO',	 \
'565-RPRPTCO','592-ORDCO', \ )

# For Adding UniversalAllocator or AmmoPacker to OSC
recipeQueryOSCAgent=\
 SELECT COMPONENT_ALIB_ID FROM alib_component WHERE COMPONENT_TYPE = 'agent' AND COMPONENT_NAME='OSC'

# Find all agents that are AL-Managers
recipeQueryALManagers=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
    ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'agent'\
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'AdaptiveLogistics' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'AdaptiveLogisticsManager'

recipeQueryALMembers=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
    ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'agent'\
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'AdaptiveLogistics' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'Member'

recipeQueryALTransportMembers=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
    ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'agent'\
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'AdaptiveLogistics' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'Member' \
    AND CA.COMMUNITY_ID LIKE '%TRANSPORT-COMM'

recipeQueryALSupplyMembers=\
SELECT DISTINCT AC.COMPONENT_ALIB_ID FROM \
   alib_component AC, \
   community_attribute CA, \
   community_entity_attribute CEA, \
   asb_component_hierarchy ACH, \
   expt_trial ET, \
   expt_trial_assembly ETA, \
   asb_assembly AA \
WHERE \
    ACH.ASSEMBLY_ID :assembly_match: \
    AND (ACH.COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID OR \
    ACH.PARENT_COMPONENT_ALIB_ID = AC.COMPONENT_ALIB_ID) \
    AND AC.COMPONENT_NAME = CEA.ENTITY_ID \
    AND CEA.COMMUNITY_ID = CA.COMMUNITY_ID \
    AND ET.TRIAL_ID = ':trial_id:' \
    AND ET.TRIAL_ID = ETA.TRIAL_ID \
    AND AA.ASSEMBLY_TYPE = 'COMM' \
    AND AA.ASSEMBLY_ID = ETA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CA.ASSEMBLY_ID \
    AND ETA.ASSEMBLY_ID = CEA.ASSEMBLY_ID \
    AND AC.COMPONENT_TYPE = 'agent'\
    AND CA.ATTRIBUTE_ID = 'CommunityType' \
    AND CA.ATTRIBUTE_VALUE = 'AdaptiveLogistics' \
    AND CEA.ATTRIBUTE_ID = 'Role' \
    AND CEA.ATTRIBUTE_VALUE = 'Member' \
    AND CA.COMMUNITY_ID LIKE '%SUPPLY-COMM'


recipeQueryTRANSCOMSubsetOfAgents= \
SELECT DISTINCT COMPONENT_ALIB_ID FROM alib_component \
WHERE \
COMPONENT_TYPE = 'agent' \
AND (COMPONENT_NAME = 'TRANSCOM' \
OR COMPONENT_NAME = 'CONUSGround' \
OR COMPONENT_NAME = 'GlobalAir' \
OR COMPONENT_NAME = 'GlobalSea' \
OR COMPONENT_NAME = 'PlanePacker' \
OR COMPONENT_NAME = 'ShipPacker' \
OR COMPONENT_NAME = 'TheaterGround')

recipeQuerySubsetOfAgents= \
SELECT DISTINCT COMPONENT_ALIB_ID FROM alib_component \
WHERE \
COMPONENT_TYPE = 'agent' \
AND (COMPONENT_NAME = '47-FSB' \
OR COMPONENT_NAME = '123-MSB' \
OR COMPONENT_NAME = '110-POL-SUPPLYCO' \
OR COMPONENT_NAME = '102-POL-SUPPLYCO' \
OR COMPONENT_NAME = '191-ORDBN' \
OR COMPONENT_NAME = '343-SUPPLYCO' \
OR COMPONENT_NAME = '565-RPRPTCO' \
OR COMPONENT_NAME = '592-ORDCO')

recipeQueryExceptPlanLogAgent=\
SELECT COMPONENT_ALIB_ID FROM ALIB_COMPONENT WHERE COMPONENT_TYPE='agent' AND COMPONENT_NAME<>'PlanLogAgent'

recipeQueryPSUSubsetOfAgents= \
SELECT DISTINCT COMPONENT_ALIB_ID FROM alib_component \
WHERE \
COMPONENT_TYPE = 'agent' \
AND (COMPONENT_NAME = '21-TSC-HQ' \
OR COMPONENT_NAME = '5-CORPS-ARTY' \
OR COMPONENT_NAME = '5-CORPS-REAR' \
OR COMPONENT_NAME = '102-POL-SUPPLYCO' \
OR COMPONENT_NAME = '110-POL-SUPPLYCO' \
OR COMPONENT_NAME = '1-13-ARBN' \
OR COMPONENT_NAME = '1-1-CAVSQDN' \
OR COMPONENT_NAME = '123-MSB' \
OR COMPONENT_NAME = '125-FSB' \
OR COMPONENT_NAME = '125-ORDBN' \
OR COMPONENT_NAME = '127-DASB' \
OR COMPONENT_NAME = '1-27-FABN' \
OR COMPONENT_NAME = '1-35-ARBN' \
OR COMPONENT_NAME = '1-36-INFBN' \
OR COMPONENT_NAME = '1-37-ARBN' \
OR COMPONENT_NAME = '1-41-INFBN' \
OR COMPONENT_NAME = '1-501-AVNBN' \
OR COMPONENT_NAME = '16-ENGBN' \
OR COMPONENT_NAME = '1-6-INFBN' \
OR COMPONENT_NAME = '191-ORDBN' \
OR COMPONENT_NAME = '1-94-FABN' \
OR COMPONENT_NAME = '1-AD' \
OR COMPONENT_NAME = '227-SUPPLYCO' \
OR COMPONENT_NAME = '2-37-ARBN' \
OR COMPONENT_NAME = '2-3-FABN' \
OR COMPONENT_NAME = '240-SSCO' \
OR COMPONENT_NAME = '244-ENGBN-CBTHVY' \
OR COMPONENT_NAME = '2-4-FABN-MLRS' \
OR COMPONENT_NAME = '2-501-AVNBN' \
OR COMPONENT_NAME = '2-6-INFBN' \
OR COMPONENT_NAME = '2-70-ARBN' \
OR COMPONENT_NAME = '3-13-FABN-155' \
OR COMPONENT_NAME = '343-SUPPLYCO' \
OR COMPONENT_NAME = '3-SUPCOM-HQ' \
OR COMPONENT_NAME = '40-ENGBN' \
OR COMPONENT_NAME = '4-1-FABN' \
OR COMPONENT_NAME = '4-27-FABN' \
OR COMPONENT_NAME = '47-FSB' \
OR COMPONENT_NAME = '501-FSB' \
OR COMPONENT_NAME = '565-RPRPTCO' \
OR COMPONENT_NAME = '592-ORDCO' \
OR COMPONENT_NAME = '597-MAINTCO' \
OR COMPONENT_NAME = '70-ENGBN' \
OR COMPONENT_NAME = '900-POL-SUPPLYCO' \
OR COMPONENT_NAME = 'CONUSGround' \
OR COMPONENT_NAME = 'DLAHQ' \
OR COMPONENT_NAME = 'GlobalAir' \
OR COMPONENT_NAME = 'GlobalSea' \
OR COMPONENT_NAME = 'HNS' \
OR COMPONENT_NAME = 'OSC' \
OR COMPONENT_NAME = 'PlanePacker' \
OR COMPONENT_NAME = 'ShipPacker' \
OR COMPONENT_NAME = 'TheaterGround' \
OR COMPONENT_NAME = 'TRANSCOM')

recipeQueryTaskFloodPlugin=\
 SELECT 'com.centurylogix.cougaar.sensors.test.TaskFloodPlugin', 'plugin', 'com.centurylogix.cougaar.sensors.test.TaskFloodPlugin' \
   FROM DUAL

recipeQueryTargetPlugin=\
 SELECT 'com.centurylogix.cougaar.sensors.test.TargetPlugin', 'plugin', 'com.centurylogix.cougaar.sensors.test.TargetPlugin' \
   FROM DUAL

recipeQueryFBSensorPlugin=\
 SELECT 'com.centurylogix.cougaar.sensors.FBSensorPlugin', 'plugin', 'com.centurylogix.cougaar.sensors.FBSensorPlugin' \
   FROM DUAL

recipeQueryTestPlugin=\
 SELECT 'com.centurylogix.cougaar.sensors.TestPlugin', 'plugin', 'com.centurylogix.cougaar.sensors.TestPlugin' \
   FROM DUAL

recipeQueryTimestampServicePlugin=\
 SELECT 'org.cougaar.core.plugin.TimestampServicePlugin', 'plugin', 'org.cougaar.core.plugin.TimestampServicePlugin' \
   FROM DUAL

recipeQueryCPUStressorPlugin=\
 SELECT 'org.cougaar.tools.cpustressor.CPUStressorPlugin', 'plugin', 'org.cougaar.tools.cpustressor.CPUStressorPlugin' \
   FROM DUAL

recipeQueryConditionServiceProvider=\
 SELECT 'org.cougaar.core.adaptivity.ConditionServiceProvider', 'plugin', 'org.cougaar.core.adaptivity.ConditionServiceProvider' \
   FROM DUAL

recipeQuerySensorServlet=\
 SELECT 'com.centurylogix.cougaar.sensors.servlet.SensorServlet', 'servlet', 'com.centurylogix.cougaar.sensors.servlet.SensorServlet' \
   FROM DUAL

# Find some agents by name - in this case, subordinates of 2BDE
recipeQueryFBSensorAgents_ByName=\
 SELECT C.COMPONENT_ALIB_ID \
   FROM alib_component C, asb_component_hierarchy H \
  WHERE C.COMPONENT_TYPE='agent' \
    AND (H.COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID OR H.PARENT_COMPONENT_ALIB_ID = C.COMPONENT_ALIB_ID) \
    AND H.ASSEMBLY_ID :assembly_match: \
    AND C.COMPONENT_NAME in ('47-FSB', '123-MSB', '1-6-INFBN')
