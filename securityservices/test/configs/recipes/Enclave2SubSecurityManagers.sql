-- MySQL dump 9.07
--
-- Host: localhost    Database: tempcopy
---------------------------------------------------------
-- Server version	4.0.12

--
-- Dumping data for table 'alib_component'
--

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager','Enclave2Sub1Manager','Enclave2Sub1Manager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2SubSecurityManagers','Enclave2SubSecurityManagers','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.adaptivity.AdaptivityEngine','Enclave2Sub1Manager|org.cougaar.core.adaptivity.AdaptivityEngine','plugin|org.cougaar.core.adaptivity.AdaptivityEngine','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.adaptivity.ConditionServiceProvider','Enclave2Sub1Manager|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','Enclave2Sub1Manager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.adaptivity.PlaybookManager','Enclave2Sub1Manager|org.cougaar.core.adaptivity.PlaybookManager','plugin|org.cougaar.core.adaptivity.PlaybookManager','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','plugin|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','plugin|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','plugin|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','plugin|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave2Sub1Manager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub1Manager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave2Sub1Manager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager','Enclave2Sub2Manager','Enclave2Sub2Manager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.adaptivity.AdaptivityEngine','Enclave2Sub2Manager|org.cougaar.core.adaptivity.AdaptivityEngine','plugin|org.cougaar.core.adaptivity.AdaptivityEngine','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.adaptivity.ConditionServiceProvider','Enclave2Sub2Manager|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','Enclave2Sub2Manager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.adaptivity.PlaybookManager','Enclave2Sub2Manager|org.cougaar.core.adaptivity.PlaybookManager','plugin|org.cougaar.core.adaptivity.PlaybookManager','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','plugin|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','plugin|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','plugin|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','plugin|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave2Sub2Manager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2Sub2Manager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave2Sub2Manager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent'
--

LOCK TABLES asb_agent WRITE;
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','Enclave2Sub1Manager',0.000000000000000000000000000000,'Enclave2Sub1Manager');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','Enclave2Sub2Manager',0.000000000000000000000000000000,'Enclave2Sub2Manager');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent_pg_attr'
--

LOCK TABLES asb_agent_pg_attr WRITE;
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','ClusterPG|MessageAddress','Enclave2Sub1Manager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','ItemIdentificationPG|AlternateItemIdentification','Enclave2Sub1Manager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','ItemIdentificationPG|ItemIdentification','Enclave2Sub1Manager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','ClusterPG|MessageAddress','Enclave2Sub2Manager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','ItemIdentificationPG|AlternateItemIdentification','Enclave2Sub2Manager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','ItemIdentificationPG|ItemIdentification','Enclave2Sub2Manager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
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
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-Enclave2SubSecurityManagers','RCP','Enclave2SubSecurityManagers');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_arg'
--

LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','Enclave2Sub1Manager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.adaptivity.PlaybookManager','AMnRPlaysEnclave.txt',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','Enclave2Sub1Manager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','org.cougaar.core.security.monitoring.plugin.AllMessageFailures',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','20',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','3600',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','org.cougaar.core.security.monitoring.MESSAGE_FAILURE',3.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','org.cougaar.core.security.monitoring.MESSAGE_FAILURE_RATE',4.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','/monitoringRegistrationViewer',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','/monitoringQueryViewer',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','Enclave2Sub2Manager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.adaptivity.PlaybookManager','AMnRPlaysEnclave.txt',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','Enclave2Sub2Manager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','org.cougaar.core.security.monitoring.plugin.AllMessageFailures',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','20',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','3600',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','org.cougaar.core.security.monitoring.MESSAGE_FAILURE',3.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','org.cougaar.core.security.monitoring.MESSAGE_FAILURE_RATE',4.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','/monitoringRegistrationViewer',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','/monitoringQueryViewer',1.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_hierarchy'
--

LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.adaptivity.PlaybookManager','Enclave2Sub2Manager','COMPONENT',10.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','Enclave2Sub2Manager','COMPONENT',9.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.adaptivity.ConditionServiceProvider','Enclave2Sub2Manager','COMPONENT',8.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.adaptivity.AdaptivityEngine','Enclave2Sub2Manager','COMPONENT',7.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','Enclave2Sub2Manager','COMPONENT',6.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','Enclave2Sub2Manager','COMPONENT',5.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','Enclave2Sub2Manager','COMPONENT',4.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','Enclave2Sub2Manager','COMPONENT',3.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','Enclave2Sub2Manager','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave2Sub2Manager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave2Sub2Manager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager','Enclave2SubSecurityManagers','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','Enclave2Sub1Manager','COMPONENT',13.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','Enclave2Sub1Manager','COMPONENT',12.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','Enclave2Sub1Manager','COMPONENT',11.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.adaptivity.PlaybookManager','Enclave2Sub1Manager','COMPONENT',10.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','Enclave2Sub1Manager','COMPONENT',9.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.adaptivity.ConditionServiceProvider','Enclave2Sub1Manager','COMPONENT',8.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.adaptivity.AdaptivityEngine','Enclave2Sub1Manager','COMPONENT',7.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','Enclave2Sub1Manager','COMPONENT',6.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','Enclave2Sub1Manager','COMPONENT',5.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','Enclave2Sub1Manager','COMPONENT',4.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','Enclave2Sub1Manager','COMPONENT',3.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','Enclave2Sub1Manager','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.mlm.plugin.organization.OrgDataPlugin','Enclave2Sub1Manager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager','Enclave2SubSecurityManagers','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub1Manager|org.cougaar.mlm.plugin.organization.OrgReportPlugin','Enclave2Sub1Manager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','Enclave2Sub2Manager','COMPONENT',13.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','Enclave2Sub2Manager','COMPONENT',12.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-Enclave2SubSecurityManagers','Enclave2Sub2Manager|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','Enclave2Sub2Manager','COMPONENT',11.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave2Sub1Manager','Enclave2Sub1Manager','MilitaryOrganization');
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('Enclave2Sub2Manager','Enclave2Sub2Manager','MilitaryOrganization');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_component'
--

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave2Sub1Manager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.AdaptivityEngine','plugin','org.cougaar.core.adaptivity.AdaptivityEngine','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin','org.cougaar.core.adaptivity.ConditionServiceProvider','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin','org.cougaar.core.adaptivity.OperatingModeServiceProvider','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.PlaybookManager','plugin','org.cougaar.core.adaptivity.PlaybookManager','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin','org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin','org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','plugin','org.cougaar.core.security.monitoring.plugin.EventQueryPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin','org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin','org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','plugin','org.cougaar.core.security.monitoring.plugin.RateCalculatorPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','plugin','org.cougaar.core.security.monitoring.servlet.MnRRegistrationViewerComponent','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','plugin','org.cougaar.core.security.monitoring.servlet.MnRResponseViewerComponent','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin','org.cougaar.mlm.plugin.organization.OrgDataPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Creates org assets, RFD (Replaces OrgRTDataPlugin and OrgTPRTDataPlugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin','org.cougaar.mlm.plugin.organization.OrgReportPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Subscribes to RFD tasks and RFS tasks and generate');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave2Sub2Manager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe'
--

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001Enclave2SubSecurityManagersEnclave2SubSecurityManagers','Enclave2SubSecurityManagers','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe_arg'
--

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001Enclave2SubSecurityManagersEnclave2SubSecurityManagers','Assembly Id',0.000000000000000000000000000000,'RCP-0001-Enclave2SubSecurityManagers');
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

