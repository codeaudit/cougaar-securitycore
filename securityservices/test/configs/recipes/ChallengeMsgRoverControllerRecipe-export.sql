# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRoverController','ChallengeMsgRoverController','ChallengeMsgRoverController','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','ChallengeMsgRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','plugin|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRoverController|org.cougaar.lib.rover.ui.RoverControlUIServlet','ChallengeMsgRoverController|org.cougaar.lib.rover.ui.RoverControlUIServlet','plugin|org.cougaar.lib.rover.ui.RoverControlUIServlet','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRoverControllerRecipe','ChallengeMsgRoverControllerRecipe','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeMsgRoverController|org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','ChallengeMsgRoverController|org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','plugin|org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController','ChallengeMsgRoverController',0.000000000000000000000000000000,'ChallengeMsgRoverController');
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
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','RCP','ChallengeMsgRoverRecipe [1]');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController','ChallengeMsgRoverController',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController|org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','RoverName=ChallengeMsgRover',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController|org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','RemoveIncomingReports=false',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','RoverName=ChallengeMsgRover',1.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','ChallengeMsgRoverController','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController|org.cougaar.lib.rover.ui.RoverControlUIServlet','ChallengeMsgRoverController','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController','ChallengeMsgRoverControllerRecipe','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-ChallengeMsgRoverControllerRecipe-Challen','ChallengeMsgRoverController|org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','ChallengeMsgRoverController','COMPONENT',0.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('ChallengeMsgRoverController','ChallengeMsgRoverController','MilitaryOrganization');
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('ChallengeMsgRoverController','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','plugin','org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.ui.RoverControlUIServlet','plugin','org.cougaar.lib.rover.ui.RoverControlUIServlet','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','plugin','org.cougaar.lib.rover.sensors.message.Message_ControllerPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001ChallengeMsgRoverControllerRecipeChallengeMsgRoverControllerRecipe','ChallengeMsgRoverControllerRecipe','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001ChallengeMsgRoverControllerRecipeChallengeMsgRoverControllerRecipe','Assembly Id',0.000000000000000000000000000000,'RCP-0001-ChallengeMsgRoverControllerRecipe-Challen');
UNLOCK TABLES;

#
# Dumping data for table 'lib_pg_attribute'
#

LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

