# MySQL dump 8.14
#
# Host: u093    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager','SocietySecurityMnRManager','SocietySecurityMnRManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager-cpy-cpy','SocietySecurityMnRManager-cpy-cpy','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.adaptivity.AdaptivityEngine','SocietySecurityMnRManager|org.cougaar.core.adaptivity.AdaptivityEngine','plugin|org.cougaar.core.adaptivity.AdaptivityEngine','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.adaptivity.ConditionServiceProvider','SocietySecurityMnRManager|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','SocietySecurityMnRManager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.adaptivity.PlaybookManager','SocietySecurityMnRManager|org.cougaar.core.adaptivity.PlaybookManager','plugin|org.cougaar.core.adaptivity.PlaybookManager','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('SocietySecurityMnRManager|org.cougaar.core.servlet.BlackboardServletComponent','SocietySecurityMnRManager|org.cougaar.core.servlet.BlackboardServletComponent','plugin|org.cougaar.core.servlet.BlackboardServletComponent','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','SocietySecurityMnRManager',0.000000000000000000000000000000,'SocietySecurityMnRManager');
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent_pg_attr'
#

LOCK TABLES asb_agent_pg_attr WRITE;
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','ClusterPG|ClusterIdentifier','SocietySecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','ItemIdentificationPG|AlternateItemIdentification','SocietySecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','ItemIdentificationPG|ItemIdentification','SocietySecurityMnRManager',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
INSERT INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
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
INSERT INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','RCP','SocietySecurityMnRManager-cpy-cpy');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','SocietySecurityMnRManager',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.adaptivity.PlaybookManager','AMnRPlaysSocietyManager.txt',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.servlet.BlackboardServletComponent','/aeviewer',2.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.servlet.BlackboardServletComponent','org.cougaar.core.adaptivity.AEViewerServlet',1.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.adaptivity.PlaybookManager','SocietySecurityMnRManager','COMPONENT',8.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.adaptivity.OperatingModeServiceProvider','SocietySecurityMnRManager','COMPONENT',7.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.servlet.BlackboardServletComponent','SocietySecurityMnRManager','COMPONENT',4.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.adaptivity.AdaptivityEngine','SocietySecurityMnRManager','COMPONENT',5.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.adaptivity.ConditionServiceProvider','SocietySecurityMnRManager','COMPONENT',6.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','SocietySecurityMnRManager','COMPONENT',3.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','SocietySecurityMnRManager','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','SocietySecurityMnRManager','COMPONENT',2.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','SocietySecurityMnRManager','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0010-SocietySecurityMnRManager-SocietySecurity','SocietySecurityMnRManager','SocietySecurityMnRManager-cpy-cpy','COMPONENT',0.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('SocietySecurityMnRManager','SocietySecurityMnRManager','MilitaryOrganization');
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('SocietySecurityMnRManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.AdaptivityEngine','plugin','org.cougaar.core.adaptivity.AdaptivityEngine','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.ConditionServiceProvider','plugin','org.cougaar.core.adaptivity.ConditionServiceProvider','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.OperatingModeServiceProvider','plugin','org.cougaar.core.adaptivity.OperatingModeServiceProvider','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.PlaybookManager','plugin','org.cougaar.core.adaptivity.PlaybookManager','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','plugin','org.cougaar.core.security.monitoring.plugin.CapabilitiesConsolidationPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','plugin','org.cougaar.core.security.monitoring.plugin.CapabilitiesProcessingPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','plugin','org.cougaar.core.security.monitoring.plugin.MnRQueryReceiverPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','plugin','org.cougaar.core.security.monitoring.plugin.MnRQueryResponderPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.servlet.BlackboardServletComponent','plugin','org.cougaar.core.servlet.BlackboardServletComponent','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0010SocietySecurityMnRManagerSocietySecurityMnRManager-cpy','SocietySecurityMnRManager-cpy-cpy','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0010SocietySecurityMnRManagerSocietySecurityMnRManager-cpy','Assembly Id',0.000000000000000000000000000000,'RCP-0010-SocietySecurityMnRManager-SocietySecurity');
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

