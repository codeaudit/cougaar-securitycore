-- MySQL dump 9.07
--
-- Host: localhost    Database: tempcopy
---------------------------------------------------------
-- Server version	4.0.12

--
-- Dumping data for table 'alib_component'
--

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1PersistenceManager','Enclave1PersistenceManager','Enclave1PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('EnclavePersistenceManagers','EnclavePersistenceManagers','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave1PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','plugin|org.cougaar.core.security.certauthority.CaServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave1PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2PersistenceManager','Enclave2PersistenceManager','Enclave2PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave2PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','plugin|org.cougaar.core.security.certauthority.CaServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave2PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3PersistenceManager','Enclave3PersistenceManager','Enclave3PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave3PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','plugin|org.cougaar.core.security.certauthority.CaServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave3PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4PersistenceManager','Enclave4PersistenceManager','Enclave4PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave4PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','plugin|org.cougaar.core.security.certauthority.CaServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave4PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent'
--

LOCK TABLES asb_agent WRITE;
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','Enclave1PersistenceManager',0.000000000000000000000000000000,'Enclave1PersistenceManager');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','Enclave2PersistenceManager',0.000000000000000000000000000000,'Enclave2PersistenceManager');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','Enclave3PersistenceManager',0.000000000000000000000000000000,'Enclave3PersistenceManager');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','Enclave4PersistenceManager',0.000000000000000000000000000000,'Enclave4PersistenceManager');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent_pg_attr'
--

LOCK TABLES asb_agent_pg_attr WRITE;
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','ClusterPG|MessageAddress','Enclave1PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','ItemIdentificationPG|AlternateItemIdentification','Enclave1PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','ItemIdentificationPG|ItemIdentification','Enclave1PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','ClusterPG|MessageAddress','Enclave2PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','ItemIdentificationPG|AlternateItemIdentification','Enclave2PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','ItemIdentificationPG|ItemIdentification','Enclave2PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','ClusterPG|MessageAddress','Enclave3PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','ItemIdentificationPG|AlternateItemIdentification','Enclave3PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','ItemIdentificationPG|ItemIdentification','Enclave3PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','ClusterPG|MessageAddress','Enclave4PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','ItemIdentificationPG|AlternateItemIdentification','Enclave4PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','ItemIdentificationPG|ItemIdentification','Enclave4PersistenceManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
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
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-EnclavePersistenceManagers','RCP','EnclavePersistenceManagers');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_arg'
--

LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','Enclave1PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','Enclave2PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','Enclave3PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','Enclave4PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_hierarchy'
--

LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave4PersistenceManager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager','EnclavePersistenceManagers','COMPONENT',3.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave3PersistenceManager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave3PersistenceManager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave3PersistenceManager','EnclavePersistenceManagers','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave2PersistenceManager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave2PersistenceManager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave2PersistenceManager','EnclavePersistenceManagers','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave1PersistenceManager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager','EnclavePersistenceManagers','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave1PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave1PersistenceManager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers','Enclave4PersistenceManager|org.cougaar.core.security.certauthority.CaServletComponent','Enclave4PersistenceManager','COMPONENT',1.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave1PersistenceManager','Enclave1PersistenceManager','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave2PersistenceManager','Enclave2PersistenceManager','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave3PersistenceManager','Enclave3PersistenceManager','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave4PersistenceManager','Enclave4PersistenceManager','MilitaryOrganization');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_component'
--

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave1PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.certauthority.CaServletComponent','plugin','org.cougaar.core.security.certauthority.CaServletComponent','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin','org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave2PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave3PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave4PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe'
--

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001EnclavePersistenceManagers','EnclavePersistenceManagers','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe_arg'
--

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001EnclavePersistenceManagers','Assembly Id',0.000000000000000000000000000000,'RCP-0001-EnclavePersistenceManagers');
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

