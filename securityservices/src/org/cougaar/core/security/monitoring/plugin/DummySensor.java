/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package org.cougaar.core.security.monitoring.plugin;

import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import edu.jhuapl.idmef.*;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import org.cougaar.core.service.*;

// Cougaar security services
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;

/** A dummy sensor used to show how to register capabilities and
 *  publish IDMEF events.
 *
 *  The cmr domain should be added to the node. This can be done by
 *  adding the following line in the LDMDomains.ini file:
 *     cmr=org.cougaar.core.security.monitoring.blackboard.CmrDomain
 */
public class DummySensor
  extends  ComponentPlugin
  implements SensorInfo
{
  private DomainService domainService = null;
  private LoggingService log;

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
    
  protected void setupSubscriptions() {
    log = (LoggingService)
	getBindingSite().getServiceBroker().getService(this,
	LoggingService.class, null);

    log.debug("setupSubscriptions of dummy sensor called :"); 
    DomainService service=getDomainService();
    if(service==null) {
      log.debug(" Got service as null in CapabilitiesConsolidationPlugin :");
      return;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    if (factory == null) {
      log.debug("Error: Unable to get Monitoring Factory");
      return;
    }    
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    DummySensor sensor=new DummySensor();
	
    // create list of capabilities
    List capabilities = new ArrayList();
    capabilities.add( imessage.createClassification( "Cougaar.security.nai.PingOfDeath",
						     "http://foo.com/security/pod.html",
						     Classification.VENDOR_SPECIFIC  ) );
    capabilities.add( imessage.createClassification( "Cougaar.security.nai.TCPSCAN", null,
						     Classification.VENDOR_SPECIFIC  ) );
    capabilities.add( imessage.createClassification( "Cougaar.security.nai.LOGINFAILURE", null,
						     Classification.VENDOR_SPECIFIC  ) );
    // no need to specify targets since we may not know of the targets
    RegistrationAlert reg=
      imessage.createRegistrationAlert(this,
				       capabilities,IdmefMessageFactory.newregistration,IdmefMessageFactory.SensorType);
    // log.debug(" Registration object is :"+reg);
    log.debug("factory is :"+factory.toString());
    NewEvent event=factory.newEvent(reg);
    log.debug(" going to publish capabilities :");
    getBlackboardService().publishAdd(event);
    log.debug("Success in publishing  capabilities :");


    /* ---------------------------------------------------------------- */
    // ********************************
    // Source

    // Make a node
    Address source_address_list[] =
    {new Address("10.1.1.1", null, null, null, null, null),
     new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
               null, null)};
    IDMEF_Node source_node = new IDMEF_Node("locationA",
                                          "attackerA",
                                          source_address_list,
                                          "id01",
                                          IDMEF_Node.DNS);
    // Make a user
    UserId source_userId_list[] = {new UserId("Attacker_User",
				       new Integer (100),
				       "Test_Ident1", UserId.CURRENT_USER)};
    
    User source_user = new User(source_userId_list, "Test_Ident1", User.APPLICATION);

    // Make a Process
    String source_arg_list[] = {"-r", "-b", "12.3.4.5"};
    String source_env_list[] = {"HOME=/home/testuser/", "PATH=/usr/sbin"};
    IDMEF_Process source_process = new IDMEF_Process("Killer-process",
						     new Integer(666),
						     "/usr/bin/Killer",
						     source_arg_list, source_env_list,
						     "Test_IdentProcess1");
    // Create a service
    Service source_service = null;
    // Make a source
    Source source = imessage.createSource(source_node,
					  source_user,
					  source_process,
					  source_service,
					  Source.YES);
    ArrayList sources = new ArrayList(1);
    sources.add(source);

    // ********************************
    // Target

    // Make a node
    Address target_address_list[] =
    {new Address("10.1.1.1", null, null, null, null, null),
     new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
               null, null)};
    IDMEF_Node target_node = new IDMEF_Node("locationB",
                                          "victimB",
                                          target_address_list,
                                          "id02",
                                          IDMEF_Node.DNS);
    // Make a user
    UserId target_userId_list[] = {new UserId("Victim_User",
					      new Integer (123),
					      "Test_Ident2", UserId.CURRENT_USER)};
    
    User target_user = new User(target_userId_list, "Test_Ident2", User.APPLICATION);

    // Make a Process
    String target_arg_list[] = {"12"};
    String target_env_list[] = {"HOME=/home/victimuser/", "PATH=/usr/sbin"};
    IDMEF_Process target_process = new IDMEF_Process("Node-process",
						     new Integer(1002),
						     "/usr/bin/Node",
						     target_arg_list, target_env_list,
						     "Test_IdentProcess");
    // Create a service
    Service target_service = null;
    // Create a file list
    FileList target_fileList = null;
    Target target = imessage.createTarget(target_node,
					  target_user,
					  target_process,
					  target_service,
					  target_fileList,
					  Target.YES);
    ArrayList targets = new ArrayList(1);
    targets.add(target);
    Classification classification =
      imessage.createClassification("cougaar_signature_exception",
				    "http://www.cougaar.org",
				    Classification.VENDOR_SPECIFIC);
    ArrayList classifications = new ArrayList(1);
    classifications.add(classification);
    ArrayList data = null;
    DetectTime detectTime = new DetectTime();
    Alert alert = imessage.createAlert(this, detectTime,
				       sources, targets,
				       classifications, data);
    Event e = factory.newEvent(alert);
    log.debug("Intrusion Alert:" + alert.toString());

    log.debug("Publishing sensor Event :");
    getBlackboardService().publishAdd(e);

  }
  public String getName(){
    return "Sample Sensor";
  }
  public String getManufacturer(){
    return "NAI Labs";
  }
  public String getModel(){
    return "Cougaar";
  }
  public String getVersion(){
    return "1.0";
  }
  public String getAnalyzerClass(){
    return "Security Analyzer";
  }
        
       
  protected void execute () {
    // process unallocated tasks
  }


}
