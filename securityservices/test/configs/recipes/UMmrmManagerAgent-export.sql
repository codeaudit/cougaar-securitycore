LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-UMmrmManagerAgentInsertion','UMmrmManagerAgentInsertion','org.cougaar.tools.csmart.recipe.AgentInsertionRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Agent Names',0.000000000000000000000000000000,'UMmrmanager');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Asset Class',3.000000000000000000000000000000,'MilitaryOrganization');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Class Name',7.000000000000000000000000000000,'org.cougaar.core.agent.ClusterImpl');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Include Item Identification PG',6.000000000000000000000000000000,'true');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Include Org Asset',1.000000000000000000000000000000,'true');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Nomenclature',4.000000000000000000000000000000,'UTC/RTOrg');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Number of Relationships',2.000000000000000000000000000000,'0');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-UMmrmManagerAgentInsertion','Type Identification',5.000000000000000000000000000000,'UTC/RTOrg');
UNLOCK TABLES;

