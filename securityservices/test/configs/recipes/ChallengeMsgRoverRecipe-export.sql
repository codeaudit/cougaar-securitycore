# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRover','ChallengeMsgRover','ChallengeMsgRover','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRoverRecipe','ChallengeMsgRoverRecipe','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_AuditorPlugIn','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_AuditorPlugIn','plugin|org.cougaar.lib.rover.sensors.message.Message_AuditorPlugIn','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_TapInspectorPlugIn','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_TapInspectorPlugIn','plugin|org.cougaar.lib.rover.sensors.message.Message_TapInspectorPlugIn','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','plugin|org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover','ChallengeMsgRover',0.000000000000000000000000000000,'ChallengeMsgRover');
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
INSERT INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','RCP','ChallengeMsgRover');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover','ChallengeMsgRover',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','MoveByAgent=true',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','Visit=1-4-ADABN+141-SIGBN+501-MIBN-CEWI+501-MPCO+69-CHEMCO+1-94-FABN+25-FABTRY-TGTACQ+1-36-INFBN+1-37-ARBN+16-ENGBN+2-3-FABN+2-37-ARBN+1-35-ARBN+1-6-INFBN+2-6-INFBN+4-27-FABN+40-ENGBN+1-13-ARBN+1-41-INFBN+2-70-ARBN+4-1-FABN+26-SSC',2.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover','ChallengeMsgRoverRecipe','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_AuditorPlugIn','ChallengeMsgRover','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_TapInspectorPlugIn','ChallengeMsgRover','COMPONENT',2.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha','ChallengeMsgRover|org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','ChallengeMsgRover','COMPONENT',0.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('ChallengeMsgRover','ChallengeMsgRover','MilitaryOrganization');
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('ChallengeMsgRover','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.message.Message_AuditorPlugIn','plugin','org.cougaar.lib.rover.sensors.message.Message_AuditorPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.message.Message_TapInspectorPlugIn','plugin','org.cougaar.lib.rover.sensors.message.Message_TapInspectorPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','plugin','org.cougaar.lib.rover.sensors.message.Message_PilotPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0002ChallengeMsgRoverChallengeMsgRoverChallengeMsgRoverRecipeChallengeMsgRoverRecipe','ChallengeMsgRoverRecipe','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0002ChallengeMsgRoverChallengeMsgRoverChallengeMsgRoverRecipeChallengeMsgRoverRecipe','Assembly Id',0.000000000000000000000000000000,'RCP-0002-ChallengeMsgRover-ChallengeMsgRover-C-Cha');
UNLOCK TABLES;

#
# Dumping data for table 'lib_pg_attribute'
#

LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

