-- MySQL dump 8.22
--
-- Host: localhost    Database: tempcopy
---------------------------------------------------------
-- Server version	3.23.52

--
-- Dumping data for table 'alib_component'
--


LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1CRLProvider','Enclave1CRLProvider','Enclave1CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2CRLProvider','Enclave2CRLProvider','Enclave2CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('EnclaveCRLProviders','EnclaveCRLProviders','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3CRLProvider','Enclave3CRLProvider','Enclave3CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4CRLProvider','Enclave4CRLProvider','Enclave4CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent'
--


LOCK TABLES asb_agent WRITE;
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave1CRLProvider','Enclave1CRLProvider',0.000000000000000000000000000000,'Enclave1CRLProvider');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave2CRLProvider','Enclave2CRLProvider',0.000000000000000000000000000000,'Enclave2CRLProvider');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave3CRLProvider','Enclave3CRLProvider',0.000000000000000000000000000000,'Enclave3CRLProvider');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave4CRLProvider','Enclave4CRLProvider',0.000000000000000000000000000000,'Enclave4CRLProvider');
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
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','RCP','EnclaveCRLProviders');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_arg'
--


LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave3CRLProvider','Enclave3CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','/CRLRegistrationViewer',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave1CRLProvider','Enclave1CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','/CRLRegistrationViewer',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave2CRLProvider','Enclave2CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','/CRLRegistrationViewer',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave4CRLProvider','Enclave4CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','/CRLRegistrationViewer',1.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_hierarchy'
--


LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave1CRLProvider','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave2CRLProvider','EnclaveCRLProviders','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave2CRLProvider','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave2CRLProvider','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave3CRLProvider','EnclaveCRLProviders','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave3CRLProvider','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave1CRLProvider','EnclaveCRLProviders','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave1CRLProvider','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave3CRLProvider','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave4CRLProvider','EnclaveCRLProviders','COMPONENT',3.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave4CRLProvider','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Enclave4CRLProvider','COMPONENT',1.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave1CRLProvider','Enclave1CRLProvider','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave2CRLProvider','Enclave2CRLProvider','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave3CRLProvider','Enclave3CRLProvider','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave4CRLProvider','Enclave4CRLProvider','MilitaryOrganization');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_component'
--


LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave1CRLProvider','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','plugin','org.cougaar.core.security.crypto.crl.servlet.CRLRegistrationInfo','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave2CRLProvider','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin','org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave3CRLProvider','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave4CRLProvider','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe'
--


LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0002EnclaveCRLProvidersEnclaveCRLProvidersEnclaveCRLProviders','EnclaveCRLProviders','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe_arg'
--


LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0002EnclaveCRLProvidersEnclaveCRLProvidersEnclaveCRLProviders','Assembly Id',0.000000000000000000000000000000,'RCP-0002-EnclaveCRLProviders-EnclaveCRLProviders-E');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_pg_attribute'
--


LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

