Should that should be enabled all the time:
===========================================
A05-security_param.rule
A10-enclave_node_agent_components.rule 
A14-pdm_web_proxy.rule
ihmc_policy_domain_mgr_agents.rule
ihmc_policy_domain_mgr_servlet_agents.rule
loopback_protocol.rule
policy_boot_policy_list.rule
policy_init_agent_plugin.rule
policy_init_node_plugin.rule
policy_uri_map.rule
policy_user_role_map.rule
z99-commit_jar_changes.rule

Rules that use certs:
====================
A12-certificate_bootstrapper_enclaves.rule
A12-enclave_ca_config_component.rule
A25-certificate_check_aspect.rule
A26-msg_protection_aspect.rule
A30-certificate_authorities.rule
enclave_crl_providers.rule 
enclave_persistence_mgrs.rule
name_server_cert_servlet.rule
persistence_relay.rule

JAAS
====
A20-jaas_agent_binder.rule 
A22-jaas_plugin_binder.rule
A22-plugin_service_filter.rule

MSG ctrl binder
===============
A26-msg_access_ctl_binder.rule 
eventService-access-ctr-binder.rule

M&R
====
A27-security_domain_addition.rule
A31-create_root_managment_facet.rule
AGG-AggregationPlugin.rule  
AGG-AlertPlugin.rule
AGG-RemoteSubscriptionPlugin.rule
blackboard_compromise.rule
create_mnr_managers_xml.rule
enclave_security_mnr_mgrs.rule
enclave_sub_security_managers.rule
mnr_bootstrap_event_plugin.rule 
mnr_certificate_revoker_plugin.rule
mnr_compromise.rule 
mnr_data_protection_sensor.rule 
mnr_event_viewer_servlet.rule 
mnr_IdmefEventPublisher.rule
mnr_login_failure.rule
mnr_message_failure.rule
mnr_plays.rule
mnr_threatcon_servlet.rule
mnr_user_lockout_plugin.rule
society_security_mnr_mgr.rule
threatcon_level_reporter.rule
Debug servlets
==============
AdaptivityEngineViewer.rule 
community_viewer_servlet.rule 
data_protection_view_plugin.rule
ihmc_policy_viewer.rule

Config Manager
==============
configuration_manager.rule

User management
===============
user_admin_agents.rule

