-- MySQL dump 8.21
--
-- Host: localhost    Database: tempcopy
---------------------------------------------------------
-- Server version	3.23.49-nt

--
-- Dumping data for table 'alib_component'
--


LOCK TABLES alib_component WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent'
--


LOCK TABLES asb_agent WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent_pg_attr'
--


LOCK TABLES asb_agent_pg_attr WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent_relation'
--


LOCK TABLES asb_agent_relation WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_assembly'
--


LOCK TABLES asb_assembly WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_arg'
--


LOCK TABLES asb_component_arg WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_hierarchy'
--


LOCK TABLES asb_component_hierarchy WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_oplan'
--


LOCK TABLES asb_oplan WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'asb_oplan_agent_attr'
--


LOCK TABLES asb_oplan_agent_attr WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'community_attribute'
--


LOCK TABLES community_attribute WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'community_entity_attribute'
--


LOCK TABLES community_entity_attribute WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'lib_agent_org'
--


LOCK TABLES lib_agent_org WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'lib_component'
--


LOCK TABLES lib_component WRITE;
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe'
--


LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','DomainManagerPluginEnclave2-cpy','org.cougaar.tools.csmart.recipe.SpecificInsertionRecipe','No description available');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe_arg'
--


LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','Class Name',4.000000000000000000000000000000,'safe.policyManager.DomainManagerPlugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','Component Name',0.000000000000000000000000000000,'safe.policyManager.DomainManagerPluginEnclave2');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','Component Priority',2.000000000000000000000000000000,'COMPONENT');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','Number of Arguments',3.000000000000000000000000000000,'1');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','Target Component Selection Query',6.000000000000000000000000000000,'recipeQueryPolicyDomainManager2Agent');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','Type of Insertion',1.000000000000000000000000000000,'plugin');
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0009DomainManagerPluginEnclave2','Value 1',5.000000000000000000000000000000,'PolicyDomainManager2');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_pg_attribute'
--


LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

