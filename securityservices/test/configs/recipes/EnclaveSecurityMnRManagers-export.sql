# MySQL dump 8.16
#
# Host: localhost    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1SecurityMnRManager','Enclave1SecurityMnRManager','Enclave1SecurityMnRManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('EnclaveSecurityMnRManagers-cpy','EnclaveSecurityMnRManagers-cpy','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave1SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave1SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2SecurityMnRManager','Enclave2SecurityMnRManager','Enclave2SecurityMnRManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave2SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave2SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3SecurityMnRManager','Enclave3SecurityMnRManager','Enclave3SecurityMnRManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave3SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave3SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4SecurityMnRManager','Enclave4SecurityMnRManager','Enclave4SecurityMnRManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave4SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave4SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','Enclave1SecurityMnRManager',0.000000000000000000000000000000,'Enclave1SecurityMnRManager');
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','Enclave2SecurityMnRManager',0.000000000000000000000000000000,'Enclave2SecurityMnRManager');
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','Enclave3SecurityMnRManager',0.000000000000000000000000000000,'Enclave3SecurityMnRManager');
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','Enclave4SecurityMnRManager',0.000000000000000000000000000000,'Enclave4SecurityMnRManager');
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent_pg_attr'
#

LOCK TABLES asb_agent_pg_attr WRITE;
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','ClusterPG|ClusterIdentifier','Enclave1SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','ItemIdentificationPG|AlternateItemIdentification','Enclave1SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','ItemIdentificationPG|ItemIdentification','Enclave1SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','ClusterPG|ClusterIdentifier','Enclave2SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','ItemIdentificationPG|AlternateItemIdentification','Enclave2SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','ItemIdentificationPG|ItemIdentification','Enclave2SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','ClusterPG|ClusterIdentifier','Enclave3SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','ItemIdentificationPG|AlternateItemIdentification','Enclave3SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','ItemIdentificationPG|ItemIdentification','Enclave3SecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','ClusterPG|ClusterIdentifier','Enclave4SecurityMnrManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','ItemIdentificationPG|AlternateItemIdentification','Enclave4SecurityManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','ItemIdentificationPG|ItemIdentification','Enclave4SecurityManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
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
INSERT INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','RCP','EnclaveSecurityMnRManagers-cpy');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','Enclave1SecurityMnRManager',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','Enclave2SecurityMnRManager',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','Enclave3SecurityMnRManager',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','Enclave4SecurityMnRManager',1.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager','EnclaveSecurityMnRManagers-cpy','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave1SecurityMnRManager','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave1SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave1SecurityMnRManager','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager','EnclaveSecurityMnRManagers-cpy','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave2SecurityMnRManager','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave2SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave2SecurityMnRManager','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager','EnclaveSecurityMnRManagers-cpy','COMPONENT',2.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave3SecurityMnRManager','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave3SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave3SecurityMnRManager','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager','EnclaveSecurityMnRManagers-cpy','COMPONENT',3.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave4SecurityMnRManager','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclaveSecurityMnRManagers','Enclave4SecurityMnRManager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave4SecurityMnRManager','COMPONENT',1.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave1SecurityMnRManager','Enclave1SecurityMnRManager','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave2SecurityMnRManager','Enclave2SecurityMnRManager','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave3SecurityMnRManager','Enclave3SecurityMnRManager','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave4SecurityMnRManager','Enclave4SecurityMnRManager','MilitaryOrganization');
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave1SecurityMnRManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin','org.cougaar.mlm.plugin.organization.OrgDataPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Creates org assets, RFD (Replaces OrgRTDataPlugin and OrgTPRTDataPlugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin','org.cougaar.mlm.plugin.organization.OrgReportPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Subscribes to RFD tasks and RFS tasks and generate');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave2SecurityMnRManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave3SecurityMnRManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave4SecurityMnRManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001EnclaveSecurityMnRManagers','EnclaveSecurityMnRManagers-cpy','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001EnclaveSecurityMnRManagers','Assembly Id',0.000000000000000000000000000000,'RCP-0001-EnclaveSecurityMnRManagers');
UNLOCK TABLES;

#
# Dumping data for table 'lib_pg_attribute'
#

LOCK TABLES lib_pg_attribute WRITE;
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ClusterPG|ClusterIdentifier','ClusterPG','ClusterIdentifier','ClusterIdentifier','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ItemIdentificationPG|AlternateItemIdentification','ItemIdentificationPG','AlternateItemIdentification','String','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ItemIdentificationPG|ItemIdentification','ItemIdentificationPG','ItemIdentification','String','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('ItemIdentificationPG|Nomenclature','ItemIdentificationPG','Nomenclature','String','SINGLE');
REPLACE INTO lib_pg_attribute (PG_ATTRIBUTE_LIB_ID, PG_NAME, ATTRIBUTE_NAME, ATTRIBUTE_TYPE, AGGREGATE_TYPE) VALUES ('TypeIdentificationPG|TypeIdentification','TypeIdentificationPG','TypeIdentification','String','SINGLE');
UNLOCK TABLES;

