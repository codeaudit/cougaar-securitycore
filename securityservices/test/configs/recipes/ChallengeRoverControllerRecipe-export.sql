# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRoverController','ChallengeRoverController','ChallengeRoverController','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','plugin|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverMessagePlugIn','ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverMessagePlugIn','plugin|org.cougaar.lib.rover.ui.components.RoverMessagePlugIn','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRoverController|org.cougaar.lib.rover.ui.RoverControlUIServlet','ChallengeRoverController|org.cougaar.lib.rover.ui.RoverControlUIServlet','plugin|org.cougaar.lib.rover.ui.RoverControlUIServlet','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRoverControllerRecipe','ChallengeRoverControllerRecipe','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('ChallengeRoverController|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','ChallengeRoverController|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','plugin|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController','ChallengeRoverController',0.000000000000000000000000000000,'ChallengeRoverController');
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
INSERT INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','RCP','ChallengeRoverRecipe [1]');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController','ChallengeRoverController',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','RoverName=ChallengeRover',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverMessagePlugIn','RoverName=ChallengeRover',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','RoverName=ChallengeRover',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','RemoveIncomingReports=false',2.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','MoveByAgent=false',3.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','Visit=FWD-F+REAR-F',4.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','ChallengeRoverController','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.ui.components.RoverMessagePlugIn','ChallengeRoverController','COMPONENT',2.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.ui.RoverControlUIServlet','ChallengeRoverController','COMPONENT',3.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController','ChallengeRoverControllerRecipe','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-ChallengeRoverControllerRecipe-ChallengeR','ChallengeRoverController|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','ChallengeRoverController','COMPONENT',0.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('ChallengeRoverController','ChallengeRoverController','MilitaryOrganization');
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('ChallengeRoverController','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','plugin','org.cougaar.lib.rover.ui.components.RoverLocationPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.ui.components.RoverMessagePlugIn','plugin','org.cougaar.lib.rover.ui.components.RoverMessagePlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.ui.RoverControlUIServlet','plugin','org.cougaar.lib.rover.ui.RoverControlUIServlet','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','plugin','org.cougaar.lib.rover.sensors.challenge.PeriodicChallenge_ControllerPlugIn','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0002ChallengeRoverControllerRecipeChallengeRoverControllerRecipe','ChallengeRoverControllerRecipe','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0002ChallengeRoverControllerRecipeChallengeRoverControllerRecipe','Assembly Id',0.000000000000000000000000000000,'RCP-0002-ChallengeRoverControllerRecipe-ChallengeR');
UNLOCK TABLES;

#
# Dumping data for table 'lib_pg_attribute'
#

LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

