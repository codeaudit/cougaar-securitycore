# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRover','ChallengeRover','ChallengeRover','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRover|org.cougaar.lib.rover.sensors.challenge.FileRead_NodeInspectorPlugin','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.FileRead_NodeInspectorPlugin','plugin|org.cougaar.lib.rover.sensors.challenge.FileRead_NodeInspectorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRover|org.cougaar.lib.rover.sensors.challenge.SystemProperties_NodeInspectorPlugin','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.SystemProperties_NodeInspectorPlugin','plugin|org.cougaar.lib.rover.sensors.challenge.SystemProperties_NodeInspectorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRover|org.cougaar.lib.rover.sensors.challenge.FileWrite_NodeInspectorPlugin','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.FileWrite_NodeInspectorPlugin','plugin|org.cougaar.lib.rover.sensors.challenge.FileWrite_NodeInspectorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Challenge_AuditorPlugIn','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Challenge_AuditorPlugIn','plugin|org.cougaar.lib.rover.sensors.challenge.Challenge_AuditorPlugIn','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Challenge_PilotPlugIn','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Challenge_PilotPlugIn','plugin|org.cougaar.lib.rover.sensors.challenge.Challenge_PilotPlugIn','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Socket_NodeInspectorPlugin','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Socket_NodeInspectorPlugin','plugin|org.cougaar.lib.rover.sensors.challenge.Socket_NodeInspectorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRoverRecipe','ChallengeRoverRecipe','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover','ChallengeRover',0.000000000000000000000000000000,'ChallengeRover');
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
INSERT INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','RCP','ChallengeRover');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover','ChallengeRover',1.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.FileRead_NodeInspectorPlugin','ChallengeRover','COMPONENT',5.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.SystemProperties_NodeInspectorPlugin','ChallengeRover','COMPONENT',3.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.FileWrite_NodeInspectorPlugin','ChallengeRover','COMPONENT',4.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Challenge_AuditorPlugIn','ChallengeRover','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Challenge_PilotPlugIn','ChallengeRover','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover|org.cougaar.lib.rover.sensors.challenge.Socket_NodeInspectorPlugin','ChallengeRover','COMPONENT',2.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall','ChallengeRover','ChallengeRoverRecipe','COMPONENT',0.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('ChallengeRover','ChallengeRover','MilitaryOrganization');
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('ChallengeRover','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.challenge.FileRead_NodeInspectorPlugin','plugin','org.cougaar.lib.rover.sensors.challenge.FileRead_NodeInspectorPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.challenge.SystemProperties_NodeInspectorPlugin','plugin','org.cougaar.lib.rover.sensors.challenge.SystemProperties_NodeInspectorPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.challenge.FileWrite_NodeInspectorPlugin','plugin','org.cougaar.lib.rover.sensors.challenge.FileWrite_NodeInspectorPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.challenge.Challenge_AuditorPlugIn','plugin','org.cougaar.lib.rover.sensors.challenge.Challenge_AuditorPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.challenge.Challenge_PilotPlugIn','plugin','org.cougaar.lib.rover.sensors.challenge.Challenge_PilotPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.challenge.Socket_NodeInspectorPlugin','plugin','org.cougaar.lib.rover.sensors.challenge.Socket_NodeInspectorPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001ChallengeRoverChallengeRoverRecipeChallengeRoverRecipe','ChallengeRoverRecipe','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001ChallengeRoverChallengeRoverRecipeChallengeRoverRecipe','Assembly Id',0.000000000000000000000000000000,'RCP-0001-ChallengeRover-ChallengeRoverRecipe-Chall');
UNLOCK TABLES;

#
# Dumping data for table 'lib_pg_attribute'
#

LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

