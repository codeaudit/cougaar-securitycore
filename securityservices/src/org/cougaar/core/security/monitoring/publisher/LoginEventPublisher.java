/*
 * <copyright>
 *  Copyright 1997-2002 Network Associates
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

package org.cougaar.core.security.monitoring.publisher;

// cougaar core classes
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;

// securityservices classes
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.LoginFailureEvent;
import org.cougaar.core.security.monitoring.plugin.UnknownSensorInfo;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.services.auth.SecurityContextService;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.XMLUtils;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.Service;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;

// java classes
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class LoginEventPublisher extends IdmefEventPublisher {

  public LoginEventPublisher(BlackboardService bbs, SecurityContextService scs, 
    CmrFactory cmrFactory, LoggingService logger, SensorInfo info) {
    super(bbs, scs, cmrFactory, logger, info);
  }

  private List createClassifications() {
    ArrayList cfs = new ArrayList();
    cfs.add(LoginFailureEvent.LOGINFAILURE);
    return cfs;
  }

  private List createSources(String remoteAddr) {
    List addrs = new ArrayList();
    Address addr = _idmefFactory.createAddress( remoteAddr, null,
                                                Address.IPV4_ADDR );
    addrs.add(addr);
    IDMEF_Node node = _idmefFactory.createNode( null, addrs );

    Source src = _idmefFactory.createSource(node, null, null, null, null);

    List srcs = new ArrayList();
    srcs.add(src);
    return srcs;
  }

  private List createTargets(String url, int serverPort, String protocol,
                             String userName) {
    IDMEF_Node node = _idmefFactory.getNodeInfo();
    List addrs = new ArrayList();
    if (node.getAddresses() != null) {
      Address[] a = node.getAddresses();
      for (int i = 0; i < a.length; i++) {
        addrs.add(a[i]);
      } // end of for (int i = 0; i < a.length; i++)
    }

    addrs.add(_idmefFactory.createAddress(url, null, Address.URL_ADDR));

    node = _idmefFactory.createNode(node.getName(), addrs);

    IDMEF_Process process = _idmefFactory.getProcessInfo();
    Service service = _idmefFactory.createService("Cougaar Web Server",
                                                  new Integer(serverPort),
                                                  protocol);

    User user = null;
    List uids = new ArrayList();
    if (userName != null) {
      uids.add(_idmefFactory.createUserId( userName ));
    }
    if (uids.size() > 0) {
      user = _idmefFactory.createUser( uids );
    }
    Target target = _idmefFactory.createTarget(node, user, process, service,
                                               null, null);
    List targets = new ArrayList();
    targets.add(target);
    return targets;
  }

  private List createAdditionalData(String reason, String targetIdent,
                                    String data) {
    Agent agentinfo = _idmefFactory.getAgentInfo();
    String [] ref=null;
    if (agentinfo.getRefIdents()!=null) {
      String[] originalref=agentinfo.getRefIdents();
      ref=new String[originalref.length+1];
      System.arraycopy(originalref,0,ref,0,originalref.length);
      ref[originalref.length] = targetIdent;
    } else {
      ref=new String[1];
      ref[0] = targetIdent;
    }
    agentinfo.setRefIdents(ref);

    AdditionalData additionalData =
      _idmefFactory.createAdditionalData(Agent.TARGET_MEANING, agentinfo);
    List addData = new ArrayList();
    addData.add(_idmefFactory.
                createAdditionalData(AdditionalData.STRING, LoginFailureEvent.FAILURE_REASON,
                                     reason));
    addData.add(additionalData);
    if (data != null) {
      addData.add(_idmefFactory.
                  createAdditionalData(AdditionalData.STRING,
                                       "Exception", data));
    }
    return addData;
  }

  protected Event createIDMEFAlert(FailureEvent event){
    LoginFailureEvent loginEvent = (LoginFailureEvent)event;
    String remoteAddr = loginEvent.getEventSource()[0];
    String [] eventTargets = loginEvent.getEventTarget();
    String url = eventTargets[0];
    int serverPort = 0;
    try {
      serverPort = Integer.parseInt(eventTargets[1]);
    } catch (Exception ex) {}
    String protocol = eventTargets[2];
    String userName = eventTargets[3];

    List sources = createSources(remoteAddr);
    List targets = createTargets(url, serverPort, protocol,
                                 userName);
    List classifications = createClassifications();
    String targetIdent = ((Target) targets.get(0)).getIdent();
    List additionalData = createAdditionalData(
      event.getReasonIdentifier(), targetIdent,
      event.getDataIdentifier());
    Alert alert = _idmefFactory.createAlert(_sensorInfo, new DetectTime(),
                                            sources, targets,
                                            classifications,
                                            additionalData);

    return _cmrFactory.newEvent(alert);
  }
}
