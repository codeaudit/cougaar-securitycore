# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.43-nt

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-NAIMsgAccessBinder','NAIMsgAccessBinder','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-NAIMsgAccessBinder','Class Name',4.000000000000000000000000000000,'org.cougaar.core.security.access.AccessAgentBinderFactory');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-NAIMsgAccessBinder','Component Name',0.000000000000000000000000000000,'org.cougaar.core.security.access.AccessAgentBinderFactory');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-NAIMsgAccessBinder','Component Priority',2.000000000000000000000000000000,'BINDER');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-NAIMsgAccessBinder','Number of Arguments',3.000000000000000000000000000000,'0');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-NAIMsgAccessBinder','Target Component Selection Query',5.000000000000000000000000000000,'recipeQueryAllNodes');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-NAIMsgAccessBinder','Type of Insertion',1.000000000000000000000000000000,'Node.AgentManager.Binder');
UNLOCK TABLES;

