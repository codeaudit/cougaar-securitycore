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

import org.cougaar.util.UnaryPredicate;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.multicast.AttributeBasedAddress;

import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.DirectoryKeyStore;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.idmef.ConsolidatedCapabilities;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.crypto.CertificateCache;
import org.cougaar.core.security.services.util.ConfigParserService;

// Cougaar overlay
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.constants.IdmefAssessments;

import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Action;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Assessment;
import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.XMLSerializable;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Iterator;
import java.util.Map;
import java.util.HashMap;

/**
 * This class queries message failures and will revoke an agent
 * certificate if the number of maximum message failures are exceeded. 
 * The value for maximum number of message failures is obtained through
 * the MAX_MESSAGE_FAILURE Operating Modes driven by the adaptivity engine.
 * Add these lines to your agent:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.CertificateRevokerPlugin(600,86400,
 *  org.cougaar.core.security.crypto.MAX_MESSAGE_FAILURE)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(EnclaveSecurityManager,org.cougaar.core.security.monitoring.plugin.AllMessageFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the message failures for deletion. 86400 represents the amount of time to
 * keep the message failures before deleting it.
 * org.cougaar.core.security.crypto.MAX_MESSAGE_FAILURE is the operating mode
 * that the ConcreteResponder requires to determine when to take action on a culprit.
 */
public class CertificateRevokerPlugin extends ResponderPlugin {
  private static final String REVOKE_CERT_SERVLET_URI = "/RevokeCertificateServlet";
  private static final String _managerRole = "SecurityMnRManager-Enclave";
  private String _agentName;
  private KeyRingService _keyRing;
  private ServiceBroker _serviceBroker;
  
  private final static Action[] CERTIFICATE_REVOKED_ACTION = new Action[] {
    new Action(Action.OTHER, IdmefAssessments.CERTIFICATE_REVOKED)
  };
 
  private final static Assessment CERTIFICATE_REVOKED_ASSESSMENT = 
    new Assessment(null,
                   CERTIFICATE_REVOKED_ACTION,
                   new Confidence(Confidence.LOW, null));

  private final static Classification MESSAGE_FAILURE = 
    new Classification(IdmefClassifications.MESSAGE_FAILURE, "", 
                       Classification.VENDOR_SPECIFIC);
  
  private final SensorInfo _analyzer = new CRResponder(); 
  private boolean _debug = false;
  
  /**
   * The predicate indicating that we should retrieve all new
   * message failures
   */
  private static final UnaryPredicate MESSAGE_FAILURES_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Event) {
          IDMEF_Message msg = ((Event) o).getEvent();
	  if (msg instanceof RegistrationAlert ||
              msg instanceof ConsolidatedCapabilities) {
	    return false;
	  }
          if (msg instanceof Alert) {
            Alert alert = (Alert) msg;
            if (alert.getAssessment() != null) {
              return false; // never look at assessment alerts
            }
            Classification cs[] = alert.getClassifications();
            if (cs != null) {
              for (int i = 0; i < cs.length; i++) {
                if (IdmefClassifications.MESSAGE_FAILURE.equals(cs[i].getName())) {
                  return true;
                }
              }
            }
          }
        }
        return false;
      }
    };
    
  protected void setupSubscriptions() {
    super.setupSubscriptions();
    _debug = _log.isDebugEnabled();
    _serviceBroker = (ServiceBroker)getServiceBroker();
    _keyRing = (KeyRingService)_serviceBroker.getService(this,
			                                                   KeyRingService.class,
	 		                                                   null);
    AgentIdentificationService ais  = (AgentIdentificationService)
      _serviceBroker.getService(this, AgentIdentificationService.class, null);
    CommunityService cs = (CommunityService)
      _serviceBroker.getService(this, CommunityService.class,null);
    // register this responder's capabilities
    _agentName = ais.getName();
    registerCapabilities(cs, _agentName);
  }
  
  /**
   * method that takes an action against the culprit
   */
  protected void action(String culprit) throws Exception {
    String message = null;
    if(_debug) {
      _log.debug("revoking certificate of agent(" + culprit + ")");
    }
       // get the ca dn and the unique id of the agent's certificate    
    if(culprit == null || culprit == "") {
      message = "agent name not specified";
      _log.warn(message);
      throw new IllegalArgumentException(message);
    }

    List certList = _keyRing.findCert(culprit);
    if(certList == null || certList.size() == 0) {
      message = "no certificate(s) available for: " + culprit;
      _log.warn(message);
      throw new CertificateException(message);
    }
    Iterator certs = certList.iterator();
    String caDN = null;
    String reply = "";
    // for now there should only be one certificate signed by one CA
    while(certs.hasNext()) {
      CertificateStatus status = (CertificateStatus)certs.next();
      X509Certificate cert = status.getCertificate();
      if(_debug) {
        _log.debug("Found certificate dn = " + cert.getSubjectDN().getName()); 
      }
      X509Certificate []certChain = _keyRing.findCertChain(cert);
      if(certChain != null) {
        // get the CA's dn from the certificate chain
        caDN = getCADN(certChain); 
       
        if(caDN != null) {
          if(_debug) {
            _log.debug("CA DN: " + caDN);
          }
          // send request to RevokeCertificateServlet
          reply = sendRevokeCertRequest(culprit, caDN);
          if(_debug) {
            _log.debug("Revoke certificate request reply:\n" + reply);
          }
        }
        else {
          message = "No CA dn(s) where found in certificate chain for: " + culprit;
          _log.warn(message);
        }
      }
      else {
        message = "Can't get certificate chain for cert: " + cert.getSubjectDN().getName();      
        _log.warn(message);
    
      }
    }
    if(message != null) {
      throw new CertificateException(message);
    }
  }
  
  protected void publishAssessment(String culprit) {
    List sources = null; 
    List classifications = new ArrayList(1);
    List data = null;
    Source s = null;
    Agent sAgent = null;
    
    if(_debug) {
      _log.debug("publishing assessment: " + IdmefAssessments.CERTIFICATE_REVOKED);
    }
    // create source information for the IDMEF event
    if(culprit != null) {
      List sRefList = new ArrayList(1);
      Address sAddr = _idmefFactory.createAddress(culprit, null, Address.URL_ADDR);
      sources = new ArrayList(1);
      s = _idmefFactory.createSource(null, null, null, null, null);
      sRefList.add(s.getIdent());
      sAgent = _idmefFactory.createAgent(culprit, null, null, sAddr, sRefList);
      sources.add(s);
      data = new ArrayList(1);
      AdditionalData agentData = 
        _idmefFactory.createAdditionalData(Agent.SOURCE_MEANING, sAgent);
      data.add(agentData);
    }
    classifications.add(MESSAGE_FAILURE);

    Alert alert = _idmefFactory.createAlert(_analyzer, new DetectTime(),
                                            sources, null, classifications, data);
    alert.setAssessment(CERTIFICATE_REVOKED_ASSESSMENT);
    NewEvent event = _cmrFactory.newEvent(alert);
    getBlackboardService().publishAdd(event);   
  }
  
  /**
   * method to process a specific failure
   */
  protected void processFailure() {
    Enumeration iter = _failureQuery.getAddedList();
    while (iter.hasMoreElements()) {
      Event e = (Event) iter.nextElement();
      Alert alert = (Alert) e.getEvent();
      Source srcs[] = alert.getSources();
      if( srcs != null ) {
        AdditionalData data[] = alert.getAdditionalData();
        for (int i = 0; i < srcs.length; i++) {
          Agent agent = findAgent(srcs[i].getIdent(), data); 
          if (agent != null) {
            Address addr = agent.getAddress();
            if (addr != null) {
              _log.debug("adding agent(" + addr.getAddress() + ") to failure cache");
              addCulprit(addr.getAddress());
            }
          }
        }
      }
      else {
        _log.error("No sources associated with the Alert. Sensor is in "
		   + _agentName + ". Alert is:" + alert);
      }
    }  
  }
  
  /**
   * method to obtain the predicate for a specific failure
   */
  protected UnaryPredicate getFailurePredicate(){
    return MESSAGE_FAILURES_PREDICATE;
  }

  private CryptoClientPolicy getCryptoClientPolicy() {
    CryptoClientPolicy cryptoClientPolicy = null;
    try {
	    ConfigParserService configParser = 
	      (ConfigParserService)_serviceBroker.getService(this,
				                                               ConfigParserService.class,
					                                             null);
	    SecurityPolicy[] sp =
	      configParser.getSecurityPolicies(CryptoClientPolicy.class);
	      cryptoClientPolicy = (CryptoClientPolicy) sp[0];
    } 
    catch(Exception e) {
	    if (_log.isErrorEnabled()) {
	      _log.error("Can't obtain client crypto policy : " + e.getMessage());
	    }
	  }
	  return cryptoClientPolicy;
  }
 
  private String sendRevokeCertRequest(String agent, String dn) 
    throws Exception {
    String reply = "";
    String revokeCertServletURL = null;
    HttpURLConnection huc = null;
    CryptoClientPolicy policy = getCryptoClientPolicy();
    if (policy == null) {
      _log.error("cryptoClientPolicy is null");
      throw new RuntimeException("cryptoClientPolicy is null");
    }
    TrustedCaPolicy[] trustedCaPolicy = policy.getTrustedCaPolicy(); 
    String caURL = trustedCaPolicy[0].caURL;
    // construct the revoke certificate servlet url
    revokeCertServletURL = caURL.substring(0, caURL.lastIndexOf('/')) +
      REVOKE_CERT_SERVLET_URI;
    if(_debug) {
      _log.debug("Sending revoke certificate request to: " + revokeCertServletURL);
    }
    try {
      URL url = new URL(revokeCertServletURL);
      huc = (HttpURLConnection)url.openConnection();
      // Don't follow redirects automatically.
      huc.setInstanceFollowRedirects(false);
      // Let the system know that we want to do output
      huc.setDoOutput(true);
      // Let the system know that we want to do input
      huc.setDoInput(true);
      // No caching, we want the real thing
      huc.setUseCaches(false);
      // Specify the content type
      huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      huc.setRequestMethod("POST");
      PrintWriter out = new PrintWriter(huc.getOutputStream());
      StringBuffer sb = new StringBuffer();
      sb.append("agent_name=");
      sb.append(URLEncoder.encode(agent, "UTF-8"));
      sb.append("&revoke_type=agent");
      sb.append("&ca_dn=");
      sb.append(URLEncoder.encode(dn, "UTF-8"));  
      out.println(sb.toString());
      out.flush();
      out.close();
    }  
    catch(Exception e) {
      _log.warn("Unable to send revoke certificate request to CA: " + e);
      if(_debug) {
        e.printStackTrace();
      }
      throw e;
    }
    try {
      BufferedReader in =
	      new BufferedReader(new InputStreamReader(huc.getInputStream()));
      int len = 2000;     // Size of a read operation
      char [] cbuf = new char[len];
      while (in.ready()) {
      	int read = in.read(cbuf, 0, len);
      	reply = reply + new String(cbuf, 0, read);
      }
      in.close();
      reply = URLDecoder.decode(reply, "UTF-8");
    } 
    catch(Exception e) {
      _log.warn("Unable to obtain reply: " + e);
      throw e;
    }
    return reply;
  }
  
  private String getCADN(X509Certificate []certChain) {
    int len = certChain.length;
    String title = null;
    String dn = null;

    for(int i = 0; i < len; i++) {
      dn = certChain[i].getIssuerDN().getName();
      title = CertificateUtility.findAttribute(dn, "t");
      if(title.equals(CertificateCache.CERT_TITLE_CA)) {
        return dn;
      }
    }
    return null;
  }
  
  // find the agent information in the additional data that references ident
  private Agent findAgent(String ident, AdditionalData []data) {
    for(int i = 0; i < data.length; i++) {
      AdditionalData d = data[i];
      if(d.getMeaning().equals(Agent.SOURCE_MEANING) && 
         d.getType().equals(AdditionalData.XML)) {
        XMLSerializable xmlData = d.getXMLData();
        if(xmlData != null &&
           (xmlData instanceof Agent)) {
          Agent agent = (Agent)xmlData;
          String []refIdents = agent.getRefIdents();
          for(int j = 0; j < refIdents.length; j++) {
            if(ident.equals(refIdents[j])) {
              return agent;
            }
          }
        }
      }
    }
    return null;  
  }
  
  /**
   * register the capabilities of the sensor
   */
  private void registerCapabilities(CommunityService cs, String agentName){
    List capabilities = new ArrayList();
    BlackboardService bbs = getBlackboardService();
    
    Classification classification = 
      _idmefFactory.createClassification(IdmefClassifications.MESSAGE_FAILURE, null);
    capabilities.add(classification);
      
    RegistrationAlert reg = 
       _idmefFactory.createRegistrationAlert( _analyzer, 
                                              null,
                                              null,
                                              capabilities,
                                              null,
                                              _idmefFactory.newregistration,
                                              _idmefFactory.SensorType,
                                              agentName);
    NewEvent regEvent = _cmrFactory.newEvent(reg);
    // get the list of communities that this agent belongs where CommunityType is Security
    Collection communities = cs.listParentCommunities(agentName, "(CommunityType=Security)"); 
    Iterator iter = communities.iterator();
    
    if (communities.size() == 0) {
      _log.warn("Agent '" + agentName + 
        "' does not belong to any security community. Message failures won't be reported.");
    }
    else if(communities.size() > 1) {
      _log.warn("Agent '" + agentName + "' belongs to more than one security community.");
    }
    
    while(iter.hasNext()) {
      String community = iter.next().toString();
      if(isSecurityManagerLocal(cs, community, agentName)) {
        // sensor is located in same agent as the enclave security manager
        // therefore we should publish the capabilities to local blackboard
        if(_debug) {
          _log.debug("Publishing sensor capabilities to local blackboard.");
        }
        bbs.publishAdd(regEvent); 
      }
      else {
        // send the capability registeration to agents with in this community
        // that has the role specified by _managerRole
        AttributeBasedAddress messageAddress = 
          AttributeBasedAddress.getAttributeBasedAddress(community, "Role", _managerRole);
        CmrRelay relay = _cmrFactory.newCmrRelay(regEvent, messageAddress);
        if(_debug) {
          _log.debug("Sending sensor capabilities to community '" + 
                      community + "'" + ", role '" + _managerRole + "'.");
        }
        bbs.publishAdd(relay);
      }  
    }
  }
  
  /**
   * method used to determine if the message failure plugin is located in the same
   * agent as the enclave security manager
   */
  private boolean isSecurityManagerLocal(CommunityService cs, String community, String agentName) {
    Collection agents = cs.searchByRole(community, _managerRole);
    Iterator i = agents.iterator();
    
    while(i.hasNext()) {
      MessageAddress addr = (MessageAddress)i.next();
      if(addr.toString().equals(agentName)) {
        return true;
      }
    }
    return false;
  }      
  
  private class CRResponder implements SensorInfo {
    public String getName() {
      return "CertificateRevokerPlugin";
    }
    public String getManufacturer() {
      return "NAI Labs";
    }
    public String getModel(){
      return "Cougaar Certificate Revoker";
    }
    public String getVersion(){
      return "1.0";
    }
    public String getAnalyzerClass(){
      return "Cougaar Security";
    } 
  }
}
