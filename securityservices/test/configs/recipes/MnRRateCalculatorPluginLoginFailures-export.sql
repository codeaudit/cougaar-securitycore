# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.43-nt

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','MnRRateCalculatorPluginLoginFailures','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description is available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Class Name',1.000000000000000000000000000000,'org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Component Name',3.000000000000000000000000000000,'org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Component Priority',5.000000000000000000000000000000,'COMPONENT');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Number of Arguments',0.000000000000000000000000000000,'4');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Target Component Selection Query',2.000000000000000000000000000000,'recipeQuerySocietySecurityMnRAgent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Type of Insertion',4.000000000000000000000000000000,'plugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Value 1',6.000000000000000000000000000000,'20');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Value 2',6.000000000000000000000000000000,'60');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Value 3',7.000000000000000000000000000000,'org.cougaar.core.security.monitoring.LOGIN_FAILURE');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-MnRRateCalculatorPluginLoginFailures','Value 4',7.000000000000000000000000000000,'org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE');
UNLOCK TABLES;

