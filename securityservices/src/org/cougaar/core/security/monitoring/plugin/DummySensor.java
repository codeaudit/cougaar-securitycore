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

import org.cougaar.core.security.monitoring.idmef.SensorInfo;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.StateModelException ;
import java.util.Enumeration;
import org.cougaar.core.service.*;
import edu.jhuapl.idmef.*;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;


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
    System.out.println("setupSubscriptions of dummy sensor called :"); 
    DomainService service=getDomainService();
    if(service==null) {
      System.out.println(" Got service as null in CapabilitiesConsolidationPlugin :");
      return;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    if (factory == null) {
      System.out.println("Error: Unable to get Monitoring Factory");
      return;
    }
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    DummySensor sensor=new DummySensor();
    String [] events={"POD","TCPSCAN","LOGINFAILURE"};
    String [] origins={" Classification.VENDOR_SPECIFIC",
		       " Classification.VENDOR_SPECIFIC",
		       " Classification.VENDOR_SPECIFIC"};
    Registration reg=imessage.createRegistration(new DummySensor(),events,origins);
    // System.out.println(" Registration object is :"+reg);
    System.out.println("factory is :"+factory.toString());
    NewEvent event=factory.newEvent(reg);
    System.out.println(" going to publish capabilities :");
    getBlackboardService().publishAdd(event);
    System.out.println("Success in publishing  capabilities :");

    /* ---------------------------------------------------------------- */
    System.out.println("Publishing sensor Event :");
    Address source_address_list[] =
    {new Address("10.1.1.1", null, null, null, null, null),
     new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
		 null, null)};
    IDMEF_Node source_node = new IDMEF_Node("locationA",
					    "attackerA",
					    source_address_list, 
					    "id01", 
					    IDMEF_Node.DNS);
    Source source = imessage.createSource(source_node, Source.YES);
    Source []sources = new Source[1];
    sources[0] = source;

    Address target_address_list[] =
    {new Address("10.1.1.1", null, null, null, null, null),
     new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
		 null, null)};
    IDMEF_Node target_node = new IDMEF_Node("locationB",
					    "victimB",
					    target_address_list, 
					    "id02", 
					    IDMEF_Node.DNS);
    Target target = imessage.createTarget(target_node, Source.NO);
    Target []targets = new Target[1];
    targets[0] = target;

    Classification classification =
      imessage.createClassification("cougaar_signature_exception",
				    "http://www.cougaar.org",
				    Classification.VENDOR_SPECIFIC);
    Classification []classifications = new Classification[1];
    classifications[0] = classification;
    AdditionalData []data = null;
    Alert alert = imessage.createAlert(this, sources, targets, classifications, data);
    Event e = factory.newEvent(alert);
    getBlackboardService().publishAdd(e);
  }

  /* ***********************************************************************
   * SensorInfo implementation
   */
  public String getName(){
    return "DummySensor";
  }
  public String getManufacturer(){
    return "NAI Labs";
  }
  public String getModel(){
    return "Cougaar";
  }
  public String getVersion(){
    return "01";
  }
  public String getAnalyzerClass(){
    return "Security Analyzer";
  }
       
  protected void execute () {
    // process unallocated tasks
  }
}
