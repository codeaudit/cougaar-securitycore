# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.43-nt

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','MnREventQueryPluginMessageFailures2','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description is available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Class Name',1.000000000000000000000000000000,'org.cougaar.core.security.monitoring.plugin.EventQueryPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Component Name',3.000000000000000000000000000000,'org.cougaar.core.security.monitoring.plugin.EventQueryPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Component Priority',5.000000000000000000000000000000,'COMPONENT');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Number of Arguments',0.000000000000000000000000000000,'2');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Target Component Selection Query',2.000000000000000000000000000000,'recipeQueryEnclave2SecurityMnRAgent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Type of Insertion',4.000000000000000000000000000000,'plugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Value 1',6.000000000000000000000000000000,'Enclave2SecurityMnRManager');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnREventQueryPluginMessageFailures2','Value 2',7.000000000000000000000000000000,'org.cougaar.core.security.monitoring.plugin.AllMessageFailures');
UNLOCK TABLES;

