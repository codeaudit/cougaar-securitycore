# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.43-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('NAISecurityComponentsParam','NAISecurityComponentsParam','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave1Security-COMM','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave1Security-COMM','Node.AgentManager.Agent.SecurityComponent|org.cougaar.core.security.provider.SecurityComponentFactory','Node.AgentManager.Agent.SecurityComponent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave2Security-COMM','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave2Security-COMM','Node.AgentManager.Agent.SecurityComponent|org.cougaar.core.security.provider.SecurityComponentFactory','Node.AgentManager.Agent.SecurityComponent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave3Security-COMM','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave3Security-COMM','Node.AgentManager.Agent.SecurityComponent|org.cougaar.core.security.provider.SecurityComponentFactory','Node.AgentManager.Agent.SecurityComponent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave4Security-COMM','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave4Security-COMM','Node.AgentManager.Agent.SecurityComponent|org.cougaar.core.security.provider.SecurityComponentFactory','Node.AgentManager.Agent.SecurityComponent',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent_pg_attr'
#

LOCK TABLES asb_agent_pg_attr WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent_relation'
#

LOCK TABLES asb_agent_relation WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'asb_assembly'
#

LOCK TABLES asb_assembly WRITE;
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-NAISecurityComponentsParam','RCP','NAISecurityComponentsParam');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave1Security-COMM','Enclave1Security-COMM',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave2Security-COMM','Enclave2Security-COMM',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave3Security-COMM','Enclave3Security-COMM',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave4Security-COMM','Enclave4Security-COMM',1.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave1Security-COMM','NAISecurityComponentsParam','HIGH',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave2Security-COMM','NAISecurityComponentsParam','HIGH',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave3Security-COMM','NAISecurityComponentsParam','HIGH',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-NAISecurityComponentsParam','NAISecurityComponentsParam|org.cougaar.core.security.provider.SecurityComponentFactory|Enclave4Security-COMM','NAISecurityComponentsParam','HIGH',3.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_oplan'
#

LOCK TABLES asb_oplan WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'asb_oplan_agent_attr'
#

LOCK TABLES asb_oplan_agent_attr WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'community_attribute'
#

LOCK TABLES community_attribute WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'community_entity_attribute'
#

LOCK TABLES community_entity_attribute WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'lib_agent_org'
#

LOCK TABLES lib_agent_org WRITE;
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Node.AgentManager.Agent.SecurityComponent|org.cougaar.core.security.provider.SecurityComponentFactory','Node.AgentManager.Agent.SecurityComponent','org.cougaar.core.security.provider.SecurityComponentFactory','Node.AgentManager.Agent.SecurityComponent','Added Node.AgentManager.Agent.SecurityComponent');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001NAISecurityComponentsParam','NAISecurityComponentsParam','org.cougaar.tools.csmart.recipe.ComponentCollectionRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001NAISecurityComponentsParam','$$CP=org.cougaar.core.security.provider.SecurityComponentFactory-0',5.000000000000000000000000000000,'recipeQueryEnclave1SecurityCommunityNodeAgents');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001NAISecurityComponentsParam','$$CP=org.cougaar.core.security.provider.SecurityComponentFactory-1',4.000000000000000000000000000000,'recipeQueryEnclave2SecurityCommunityNodeAgents');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001NAISecurityComponentsParam','$$CP=org.cougaar.core.security.provider.SecurityComponentFactory-2',3.000000000000000000000000000000,'recipeQueryEnclave3SecurityCommunityNodeAgents');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001NAISecurityComponentsParam','$$CP=org.cougaar.core.security.provider.SecurityComponentFactory-3',2.000000000000000000000000000000,'recipeQueryEnclave4SecurityCommunityNodeAgents');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001NAISecurityComponentsParam','Assembly Id',0.000000000000000000000000000000,'RCP-0001-NAISecurityComponentsParam');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001NAISecurityComponentsParam','Target Component Selection Query',1.000000000000000000000000000000,'recipeQuerySelectNothing');
UNLOCK TABLES;

#
# Dumping data for table 'lib_pg_attribute'
#

LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

