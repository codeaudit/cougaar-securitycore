## Agent insertion is moved to UMmrmManagerAgent-export.sql

#
#LOCK TABLES lib_mod_recipe WRITE;
#REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMmrmManagerAgentInsertion','UMmrmManagerAgentInsertion','org.cougaar.tools.csmart.recipe.AgentInsertionRecipe','No description available');
#UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

#LOCK TABLES lib_mod_recipe_arg WRITE;
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Agent Names',0.000000000000000000000000000000,'UMmrmanager');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Asset Class',3.000000000000000000000000000000,'MilitaryOrganization');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Class Name',7.000000000000000000000000000000,'org.cougaar.core.agent.ClusterImpl');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Include Item Identification PG',6.000000000000000000000000000000,'true');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Include Org Asset',1.000000000000000000000000000000,'true');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Nomenclature',4.000000000000000000000000000000,'UTC/RTOrg');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Number of Relationships',2.000000000000000000000000000000,'0');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Type Identification',5.000000000000000000000000000000,'UTC/RTOrg');
#UNLOCK TABLES;

##

#LOCK TABLES lib_mod_recipe WRITE;
#REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMTestSensorAgentInsertion','UMTestSensorAgentInsertion-TestingOnly','org.cougaar.tools.csmart.recipe.AgentInsertionRecipe','No description available');
#UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

#LOCK TABLES lib_mod_recipe_arg WRITE;
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Agent Names',0.000000000000000000000000000000,'TestSensorAgent');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Asset Class',3.000000000000000000000000000000,'MilitaryOrganization');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Class Name',7.000000000000000000000000000000,'org.cougaar.core.agent.ClusterImpl');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Include Item Identification PG',6.000000000000000000000000000000,'true');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Include Org Asset',1.000000000000000000000000000000,'true');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Nomenclature',4.000000000000000000000000000000,'UTC/RTOrg');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Number of Relationships',2.000000000000000000000000000000,'0');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestSensorAgentInsertion','Type Identification',5.000000000000000000000000000000,'UTC/RTOrg');
#UNLOCK TABLES;

##

#LOCK TABLES lib_mod_recipe WRITE;
#REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMTestIDMEFGeneratorPlugin','UMTestIDMEFGeneratorPlugin-TestingOnly','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
#UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

#LOCK TABLES lib_mod_recipe_arg WRITE;
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestIDMEFGeneratorPlugin','Class Name',1.000000000000000000000000000000,'edu.memphis.issrl.mrmanager.IDMEFGeneratorPlugIn');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestIDMEFGeneratorPlugin','Component Name',3.000000000000000000000000000000,'IDMEFGeneratorPlugIn');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestIDMEFGeneratorPlugin','Component Priority',5.000000000000000000000000000000,'COMPONENT');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestIDMEFGeneratorPlugin','Number of Arguments',0.000000000000000000000000000000,'0');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestIDMEFGeneratorPlugin','Target Component Selection Query',2.000000000000000000000000000000,'recipeQueryForTestSensorAgent');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMTestIDMEFGeneratorPlugin','Type of Insertion',4.000000000000000000000000000000,'plugin');
#UNLOCK TABLES;

#
# SCAggregationComponent recipe
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMManagerServlet','UMManagerServlet','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerServlet','Class Name',4.000000000000000000000000000000,'edu.memphis.issrl.mrmanager.SCAggregationComponent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerServlet','Component Name',0.000000000000000000000000000000,'SCAggregationComponent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerServlet','Component Priority',2.000000000000000000000000000000,'COMPONENT');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerServlet','Number of Arguments',3.000000000000000000000000000000,'1');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerServlet','Target Component Selection Query',5.000000000000000000000000000000,'recipeQueryForUMmrmangerAgent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerServlet','Type of Insertion',1.000000000000000000000000000000,'plugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerServlet','Value 1',6.000000000000000000000000000000,'/manager');
UNLOCK TABLES;

#
# SCAggregationKeepAliveComponent recipe
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMManagerKeepAliveServlet','UMManagerKeepAliveServlet','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerKeepAliveServlet','Class Name',4.000000000000000000000000000000,'edu.memphis.issrl.mrmanager.SCAggregationKeepAliveComponent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerKeepAliveServlet','Component Name',0.000000000000000000000000000000,'SCAggregationComponent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerKeepAliveServlet','Component Priority',2.000000000000000000000000000000,'COMPONENT');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerKeepAliveServlet','Number of Arguments',3.000000000000000000000000000000,'1');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerKeepAliveServlet','Target Component Selection Query',5.000000000000000000000000000000,'recipeQueryForUMmrmangerAgent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerKeepAliveServlet','Type of Insertion',1.000000000000000000000000000000,'plugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMManagerKeepAliveServlet','Value 1',6.000000000000000000000000000000,'/keepalivemanager');
UNLOCK TABLES;

#
# AggregationPlugin recipe
#
LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMmrmManagerAggPlugin','UMmrmManagerAggPlugin','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAggPlugin','Class Name',4.000000000000000000000000000000,'org.cougaar.lib.aggagent.plugin.AggregationPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAggPlugin','Component Name',0.000000000000000000000000000000,'AggregationPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAggPlugin','Component Priority',2.000000000000000000000000000000,'COMPONENT');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAggPlugin','Number of Arguments',3.000000000000000000000000000000,'0');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAggPlugin','Target Component Selection Query',5.000000000000000000000000000000,'recipeQueryForUMmrmangerAgent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAggPlugin','Type of Insertion',1.000000000000000000000000000000,'plugin');
UNLOCK TABLES;


# AlertPlugin recipe

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMmrmManagerAlertPlugin','UMmrmManagerAlertPlugin','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAlertPlugin','Class Name',4.000000000000000000000000000000,'org.cougaar.lib.aggagent.plugin.AlertPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAlertPlugin','Component Name',0.000000000000000000000000000000,'AggregationPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAlertPlugin','Component Priority',2.000000000000000000000000000000,'COMPONENT');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAlertPlugin','Number of Arguments',3.000000000000000000000000000000,'0');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAlertPlugin','Target Component Selection Query',5.000000000000000000000000000000,'recipeQueryForUMmrmangerAgent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAlertPlugin','Type of Insertion',1.000000000000000000000000000000,'plugin');
UNLOCK TABLES;


##


#LOCK TABLES lib_mod_recipe WRITE;
#REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMAGG-RemoteSubscription','UMAGG-RemoteSubscription-TestingOnly','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
#UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

#LOCK TABLES lib_mod_recipe_arg WRITE;
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMAGG-RemoteSubscription','Class Name',4.000000000000000000000000000000,'org.cougaar.lib.aggagent.plugin.RemoteSubscriptionPlugin');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMAGG-RemoteSubscription','Component Name',0.000000000000000000000000000000,'org.cougaar.lib.aggagent.plugin.RemoteSubscriptionPlugin');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMAGG-RemoteSubscription','Component Priority',2.000000000000000000000000000000,'COMPONENT');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMAGG-RemoteSubscription','Number of Arguments',3.000000000000000000000000000000,'0');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMAGG-RemoteSubscription','Target Component Selection Query',5.000000000000000000000000000000,'recipeQueryForTestSensorAgent');
#REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMAGG-RemoteSubscription','Type of Insertion',1.000000000000000000000000000000,'plugin');
#UNLOCK TABLES;







