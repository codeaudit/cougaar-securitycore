# MySQL dump 8.14
#
# Host: u081    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent-cpy','IHMCPolicyDomainManagerAgent-cpy','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|org.cougaar.core.adaptivity.OperatingModePolicyManager','IHMCPolicyDomainManagerAgent|org.cougaar.core.adaptivity.OperatingModePolicyManager','plugin|org.cougaar.core.adaptivity.OperatingModePolicyManager','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|org.cougaar.core.security.policy.PolicyExpanderPlugin','IHMCPolicyDomainManagerAgent|org.cougaar.core.security.policy.PolicyExpanderPlugin','plugin|org.cougaar.core.security.policy.PolicyExpanderPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|org.cougaar.mlm.plugin.organization.OrgDataPlugin','IHMCPolicyDomainManagerAgent|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|org.cougaar.mlm.plugin.organization.OrgReportPlugin','IHMCPolicyDomainManagerAgent|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|safe.policyManager.ConditionMonitorPlugin','IHMCPolicyDomainManagerAgent|safe.policyManager.ConditionMonitorPlugin','plugin|safe.policyManager.ConditionMonitorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','plugin|safe.policyManager.DomainManagerPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|safe.policyManager.PolicyExpanderPlugin','IHMCPolicyDomainManagerAgent|safe.policyManager.PolicyExpanderPlugin','plugin|safe.policyManager.PolicyExpanderPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|safe.policyManager.SetOperatingModeServletComponent','IHMCPolicyDomainManagerAgent|safe.policyManager.SetOperatingModeServletComponent','plugin|safe.policyManager.SetOperatingModeServletComponent','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','IHMCPolicyDomainManagerAgent',0.000000000000000000000000000000,'IHMCPolicyDomainManagerAgent');
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent_pg_attr'
#

LOCK TABLES asb_agent_pg_attr WRITE;
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','ClusterPG|ClusterIdentifier','IHMCPolicyDomainManagerAgent',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','ItemIdentificationPG|AlternateItemIdentification','IHMCPolicyDomainManagerAgent',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','ItemIdentificationPG|ItemIdentification','IHMCPolicyDomainManagerAgent',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','ItemIdentificationPG|Nomenclature','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
REPLACE INTO asb_agent_pg_attr (ASSEMBLY_ID, COMPONENT_ALIB_ID, PG_ATTRIBUTE_LIB_ID, ATTRIBUTE_VALUE, ATTRIBUTE_ORDER, START_DATE, END_DATE) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','TypeIdentificationPG|TypeIdentification','UTC/RTOrg',0.000000000000000000000000000000,'2000-01-01 00:00:00',NULL);
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
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','RCP','IHMCPolicyDomainManagerAgent-cpy');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','IHMCPolicyDomainManagerAgent',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','IHMCPolicyDomainManagerDomain',1.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|org.cougaar.core.adaptivity.OperatingModePolicyManager','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',7.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|org.cougaar.core.security.policy.PolicyExpanderPlugin','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',6.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|org.cougaar.mlm.plugin.organization.OrgDataPlugin','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|org.cougaar.mlm.plugin.organization.OrgReportPlugin','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|safe.policyManager.ConditionMonitorPlugin','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',3.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|safe.policyManager.PolicyExpanderPlugin','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',5.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0004-IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent|safe.policyManager.SetOperatingModeServletComponent','IHMCPolicyDomainManagerAgent-cpy','COMPONENT',4.000000000000000000000000000000);
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
REPLACE INTO lib_agent_org (COMPONENT_LIB_ID, AGENT_LIB_NAME, AGENT_ORG_CLASS) VALUES ('IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent','MilitaryOrganization');
UNLOCK TABLES;

#
# Dumping data for table 'lib_component'
#

LOCK TABLES lib_component WRITE;
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.OperatingModePolicyManager','plugin','org.cougaar.core.adaptivity.OperatingModePolicyManager','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.policy.PolicyExpanderPlugin','plugin','org.cougaar.core.security.policy.PolicyExpanderPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.mlm.plugin.organization.OrgDataPlugin','plugin','org.cougaar.mlm.plugin.organization.OrgDataPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Creates org assets, RFD (Replaces OrgRTDataPlugin and OrgTPRTDataPlugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.mlm.plugin.organization.OrgReportPlugin','plugin','org.cougaar.mlm.plugin.organization.OrgReportPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Subscribes to RFD tasks and RFS tasks and generate');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|safe.policyManager.ConditionMonitorPlugin','plugin','safe.policyManager.ConditionMonitorPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|safe.policyManager.DomainManagerPlugin','plugin','safe.policyManager.DomainManagerPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|safe.policyManager.PolicyExpanderPlugin','plugin','safe.policyManager.PolicyExpanderPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|safe.policyManager.SetOperatingModeServletComponent','plugin','safe.policyManager.SetOperatingModeServletComponent','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0004IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent-cpy','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0004IHMCPolicyDomainManagerAgent','Assembly Id',0.000000000000000000000000000000,'RCP-0004-IHMCPolicyDomainManagerAgent');
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

