# MySQL dump 8.14
#
# Host: u081    Database: tempcopy
#--------------------------------------------------------
# Server version	3.23.44-nt

#
# Dumping data for table 'alib_component'
#

LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgentRecipe-cpy','IHMCPolicyDomainManagerAgentRecipe-cpy','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|org.cougaar.core.adaptivity.OperatingModePolicyManager','IHMCPolicyDomainManagerAgent|org.cougaar.core.adaptivity.OperatingModePolicyManager','plugin|org.cougaar.core.adaptivity.OperatingModePolicyManager','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|org.cougaar.core.security.policy.PolicyExpanderPlugin','IHMCPolicyDomainManagerAgent|org.cougaar.core.security.policy.PolicyExpanderPlugin','plugin|org.cougaar.core.security.policy.PolicyExpanderPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|safe.policyManager.ConditionMonitorPlugin','IHMCPolicyDomainManagerAgent|safe.policyManager.ConditionMonitorPlugin','plugin|safe.policyManager.ConditionMonitorPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','plugin|safe.policyManager.DomainManagerPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('IHMCPolicyDomainManagerAgent|safe.policyManager.SetOperatingModeServletComponent','IHMCPolicyDomainManagerAgent|safe.policyManager.SetOperatingModeServletComponent','plugin|safe.policyManager.SetOperatingModeServletComponent','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent'
#

LOCK TABLES asb_agent WRITE;
INSERT INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent',0.000000000000000000000000000000,'IHMCPolicyDomainManagerAgent');
UNLOCK TABLES;

#
# Dumping data for table 'asb_agent_pg_attr'
#

LOCK TABLES asb_agent_pg_attr WRITE;
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
INSERT INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','RCP','IHMCPolicyDomainManagerAgent-cpy');
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_arg'
#

LOCK TABLES asb_component_arg WRITE;
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgent',1.000000000000000000000000000000);
INSERT INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','IHMCPolicyDomainManagerAgent',1.000000000000000000000000000000);
UNLOCK TABLES;

#
# Dumping data for table 'asb_component_hierarchy'
#

LOCK TABLES asb_component_hierarchy WRITE;
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent','IHMCPolicyDomainManagerAgentRecipe-cpy','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent|org.cougaar.core.adaptivity.OperatingModePolicyManager','IHMCPolicyDomainManagerAgent','COMPONENT',4.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent|org.cougaar.core.security.policy.PolicyExpanderPlugin','IHMCPolicyDomainManagerAgent','COMPONENT',3.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent|safe.policyManager.ConditionMonitorPlugin','IHMCPolicyDomainManagerAgent','COMPONENT',1.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent|safe.policyManager.DomainManagerPlugin','IHMCPolicyDomainManagerAgent','COMPONENT',0.000000000000000000000000000000);
INSERT INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgent|safe.policyManager.SetOperatingModeServletComponent','IHMCPolicyDomainManagerAgent','COMPONENT',2.000000000000000000000000000000);
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
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('IHMCPolicyDomainManagerAgent','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.adaptivity.OperatingModePolicyManager','plugin','org.cougaar.core.adaptivity.OperatingModePolicyManager','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.policy.PolicyExpanderPlugin','plugin','org.cougaar.core.security.policy.PolicyExpanderPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|safe.policyManager.ConditionMonitorPlugin','plugin','safe.policyManager.ConditionMonitorPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|safe.policyManager.DomainManagerPlugin','plugin','safe.policyManager.DomainManagerPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|safe.policyManager.SetOperatingModeServletComponent','plugin','safe.policyManager.SetOperatingModeServletComponent','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe'
#

LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001IHMCPolicyDomainManagerAgentRecipe','IHMCPolicyDomainManagerAgentRecipe-cpy','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

#
# Dumping data for table 'lib_mod_recipe_arg'
#

LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001IHMCPolicyDomainManagerAgentRecipe','Assembly Id',0.000000000000000000000000000000,'RCP-0001-IHMCPolicyDomainManagerAgentRecipe');
UNLOCK TABLES;

#
# Dumping data for table 'lib_pg_attribute'
#

LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

