-- MySQL dump 8.22
--
-- Host: localhost    Database: tempcopy
---------------------------------------------------------
-- Server version	3.23.52

--
-- Dumping data for table 'alib_component'
--


LOCK TABLES alib_component WRITE;
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3PersistenceManager','Enclave3PersistenceManager','Enclave3PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('EnclavePersistenceManagers','EnclavePersistenceManagers','recipe|##RECIPE_CLASS##','recipe',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave3PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave3PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave3PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','plugin|org.cougaar.core.servlet.SimpleServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2PersistenceManager','Enclave2PersistenceManager','Enclave2PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1PersistenceManager','Enclave1PersistenceManager','Enclave1PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave1PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','plugin|org.cougaar.core.servlet.SimpleServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave1PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave1PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave2PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','plugin|org.cougaar.core.servlet.SimpleServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave2PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave2PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4PersistenceManager','Enclave4PersistenceManager','Enclave4PersistenceManager','agent',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave4PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','plugin|org.cougaar.core.servlet.SimpleServletComponent','plugin',0.000000000000000000000000000000);
REPLACE INTO alib_component (COMPONENT_ALIB_ID, COMPONENT_NAME, COMPONENT_LIB_ID, COMPONENT_TYPE, CLONE_SET_ID) VALUES ('Enclave4PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave4PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin',0.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_agent'
--


LOCK TABLES asb_agent WRITE;
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave1PersistenceManager','Enclave1PersistenceManager',0.000000000000000000000000000000,'Enclave1PersistenceManager');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave2PersistenceManager','Enclave2PersistenceManager',0.000000000000000000000000000000,'Enclave2PersistenceManager');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave3PersistenceManager','Enclave3PersistenceManager',0.000000000000000000000000000000,'Enclave3PersistenceManager');
REPLACE INTO asb_agent (ASSEMBLY_ID, COMPONENT_ALIB_ID, COMPONENT_LIB_ID, CLONE_SET_ID, COMPONENT_NAME) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave4PersistenceManager','Enclave4PersistenceManager',0.000000000000000000000000000000,'Enclave4PersistenceManager');
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
REPLACE INTO asb_assembly (ASSEMBLY_ID, ASSEMBLY_TYPE, DESCRIPTION) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','RCP','EnclavePersistenceManagers');
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_arg'
--


LOCK TABLES asb_component_arg WRITE;
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave1PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave1PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave1PersistenceManager','Enclave1PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave4PersistenceManager','Enclave4PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave4PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave4PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave3PersistenceManager','Enclave3PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave3PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave3PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave2PersistenceManager','Enclave2PersistenceManager',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave2PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','org.cougaar.core.security.dataprotection.plugin.KeyRecoveryServlet',1.000000000000000000000000000000);
REPLACE INTO asb_component_arg (ASSEMBLY_ID, COMPONENT_ALIB_ID, ARGUMENT, ARGUMENT_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave2PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','/KeyRecoveryServlet',2.000000000000000000000000000000);
UNLOCK TABLES;

--
-- Dumping data for table 'asb_component_hierarchy'
--


LOCK TABLES asb_component_hierarchy WRITE;
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave3PersistenceManager','EnclavePersistenceManagers','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave3PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave3PersistenceManager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave3PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave3PersistenceManager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave2PersistenceManager','EnclavePersistenceManagers','COMPONENT',2.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave1PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave1PersistenceManager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave1PersistenceManager','EnclavePersistenceManagers','COMPONENT',3.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave1PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave1PersistenceManager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave2PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave2PersistenceManager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave2PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave2PersistenceManager','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave4PersistenceManager|org.cougaar.core.servlet.SimpleServletComponent','Enclave4PersistenceManager','COMPONENT',1.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave4PersistenceManager','EnclavePersistenceManagers','COMPONENT',0.000000000000000000000000000000);
REPLACE INTO asb_component_hierarchy (ASSEMBLY_ID, COMPONENT_ALIB_ID, PARENT_COMPONENT_ALIB_ID, PRIORITY, INSERTION_ORDER) VALUES ('RCP-0001-EnclavePersistenceManagers-EnclavePersist','Enclave4PersistenceManager|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Enclave4PersistenceManager','COMPONENT',0.000000000000000000000000000000);
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
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave3PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('recipe|##RECIPE_CLASS##','recipe','##RECIPE_CLASS##','recipe','Added recipe');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','plugin','org.cougaar.core.security.dataprotection.plugin.PersistenceMgrPlugin','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('plugin|org.cougaar.core.servlet.SimpleServletComponent','plugin','org.cougaar.core.security.certauthority.CaServletComponent','Node.AgentManager.Agent.PluginManager.Plugin','Added plugin');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave2PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave1PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
REPLACE INTO lib_component (COMPONENT_LIB_ID, COMPONENT_TYPE, COMPONENT_CLASS, INSERTION_POINT, DESCRIPTION) VALUES ('Enclave4PersistenceManager','agent','org.cougaar.core.agent.ClusterImpl','Node.AgentManager.Agent','Added agent');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe'
--


LOCK TABLES lib_mod_recipe WRITE;
REPLACE INTO lib_mod_recipe (MOD_RECIPE_LIB_ID, NAME, JAVA_CLASS, DESCRIPTION) VALUES ('RECIPE-0001EnclavePersistenceManagersEnclavePersistenceManagers','EnclavePersistenceManagers','org.cougaar.tools.csmart.recipe.CompleteAgentRecipe','No description available');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_mod_recipe_arg'
--


LOCK TABLES lib_mod_recipe_arg WRITE;
REPLACE INTO lib_mod_recipe_arg (MOD_RECIPE_LIB_ID, ARG_NAME, ARG_ORDER, ARG_VALUE) VALUES ('RECIPE-0001EnclavePersistenceManagersEnclavePersistenceManagers','Assembly Id',0.000000000000000000000000000000,'RCP-0001-EnclavePersistenceManagers-EnclavePersist');
UNLOCK TABLES;

--
-- Dumping data for table 'lib_pg_attribute'
--


LOCK TABLES lib_pg_attribute WRITE;
UNLOCK TABLES;

