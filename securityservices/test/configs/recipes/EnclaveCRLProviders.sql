-- MySQL dump 9.07
--
-- Host: localhost    Database: tempcopy
---------------------------------------------------------
-- Server version	4.0.12

--
-- Dumping data for table 'alib_component'
--

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1CRLProvider','Enclave1CRLProvider','Enclave1CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('EnclaveCRLProviders','EnclaveCRLProviders','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2CRLProvider','Enclave2CRLProvider','Enclave2CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3CRLProvider','Enclave3CRLProvider','Enclave3CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4CRLProvider','Enclave4CRLProvider','Enclave4CRLProvider','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent'
--

LOCK TABLES asb_agent WRITE;
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','Enclave1CRLProvider',0.000000000000000000000000000000,'Enclave1CRLProvider');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','Enclave2CRLProvider',0.000000000000000000000000000000,'Enclave2CRLProvider');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','Enclave3CRLProvider',0.000000000000000000000000000000,'Enclave3CRLProvider');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','Enclave4CRLProvider',0.000000000000000000000000000000,'Enclave4CRLProvider');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent_pg_attr'
--

LOCK TABLES asb_agent_pg_attr WRITE;
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','ClusterPG|MessageAddress','Enclave1CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','ItemIdentificationPG|AlternateItemIdentification','Enclave1CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','ItemIdentificationPG|ItemIdentification','Enclave1CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','ClusterPG|MessageAddress','Enclave2CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','ItemIdentificationPG|AlternateItemIdentification','Enclave2CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','ItemIdentificationPG|ItemIdentification','Enclave2CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','ClusterPG|MessageAddress','Enclave3CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','ItemIdentificationPG|AlternateItemIdentification','Enclave3CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','ItemIdentificationPG|ItemIdentification','Enclave3CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','ClusterPG|MessageAddress','Enclave4CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','ItemIdentificationPG|AlternateItemIdentification','Enclave4CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','ItemIdentificationPG|ItemIdentification','Enclave4CRLProvider',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
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
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0002-EnclaveCRLProviders','RCP','EnclaveCRLProviders');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_arg'
--

LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','Enclave1CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','Enclave2CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','Enclave3CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','Enclave4CRLProvider',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','60',1.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_hierarchy'
--

LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave4CRLProvider','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave4CRLProvider','EnclaveCRLProviders','COMPONENT',3.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave3CRLProvider','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave3CRLProvider','EnclaveCRLProviders','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave2CRLProvider','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave2CRLProvider','EnclaveCRLProviders','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider','EnclaveCRLProviders','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0002-EnclaveCRLProviders','Enclave1CRLProvider|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Enclave1CRLProvider','COMPONENT',0.000000000000000000000000000000);
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
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','plugin','org.cougaar.core.security.crypto.crl.plugin.CrlAgentRegistrationPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave2CRLProvider','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave3CRLProvider','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave4CRLProvider','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe'
--

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0002EnclaveCRLProviders','EnclaveCRLProviders','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe_arg'
--

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0002EnclaveCRLProviders','Assembly Id',0.000000000000000000000000000000,'RCP-0002-EnclaveCRLProviders');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_pg_attribute'
--

LOCK TABLES lib_pg_attribute WRITE;
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ClusterPG|MessageAddress','ClusterPG','MessageAddress','MessageAddress','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ItemIdentificationPG|AlternateItemIdentification','ItemIdentificationPG','AlternateItemIdentification','String','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ItemIdentificationPG|ItemIdentification','ItemIdentificationPG','ItemIdentification','String','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ItemIdentificationPG|Nomenclature','ItemIdentificationPG','Nomenclature','String','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('TypeIdentificationPG|TypeIdentification','TypeIdentificationPG','TypeIdentification','String','SINGLE');
UNLOCK TABLES;

