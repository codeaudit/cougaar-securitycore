For MOP Test of Audit Logging, make sure auditting is turned on for the AuditTestServlet.

Use the /recipes/rules/audit_servlet.rule to add the servlet to an agent

The use the Cougaar action: InvokeAuditTestServlet  in the /acme_scripts/audit.rb to test.  It will puts true or false