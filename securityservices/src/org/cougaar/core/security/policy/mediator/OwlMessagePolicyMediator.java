
/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.policy.mediator;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.agent.service.ServiceFailure;

import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import kaos.ontology.vocabulary.ActionConcepts;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.policy.MessageAccessPermission;
import org.cougaar.core.security.policy.builder.VerbBuilder;
import org.cougaar.core.security.policy.enforcers.util.CipherSuite;
import org.cougaar.core.security.policy.enforcers.util.CipherSuiteMapping;
import org.cougaar.core.security.policy.enforcers.util.HardWired;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.services.policy.PolicyService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;

import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;

/**
 * This class is responsible for enforcing policy for Ultralog messages.
 */
public class OwlMessagePolicyMediator implements NodeEnforcer,PolicyMediator {

  private ServiceBroker _sb;
  protected LoggingService _log;
  private CommunityService _communityService;
  private CipherSuiteMapping _csm;

  private final String _enforcedActionType 
  = ActionConcepts.EncryptedCommunicationAction();

  private List                   _agents;
  private EnforcerManagerService _guard;
  
  private PolicyService _policyService;
  private MessageAddress agentAddress;

  /**
   * This returns a list of the action classes that this controls, 
   * consisting of CommunicationActions for this enforcer.
   */
  public Vector getControlledActionClasses()
    {
      Vector result = new Vector();
      result.add(_enforcedActionType);
      result.add(ActionConcepts.CommunicationAction());
      return result;
    }

  /**
   * Returns the name of the enforcer.
   */
  public String getName() {
    if(agentAddress!=null){
      return agentAddress.toString(); 
    }
    return null;
  }


  /**
   * This function initializes the ULMessageNodeEnforcer by providing it
   * with a service broker and the names of the agent it does enforcement
   * for. This agent thing is a temporary hack - it is not clear how the
   * association of agents and enforcers will take place.
   */
  public OwlMessagePolicyMediator(ServiceBroker sb, List agents)
    {
      try {
        _sb = sb;
        _csm = new CipherSuiteMapping();
        _agents=agents;
        _log = (LoggingService) 
          _sb.getService(this, LoggingService.class, null);
        HardWired.setServiceBroker(sb);
        _log.debug("Creating Community Service Proxy");
        if (!_sb.hasService(CommunityService.class)) {
          _log.debug("Community service is missing: adding listener");
          _sb.addServiceListener(new CommunityServiceListener());
        }
        else {
          _communityService = (CommunityService) 
            _sb.getService(this, CommunityService.class, null);
          if (_communityService == null) {
            _log.debug("Community service is missing");
          }
          _log.debug("Community Service Created");
          _log.debug("Community = " + _communityService);
        }
        if(!_sb.hasService(PolicyService.class)){
          if(_log.isDebugEnabled()){
            _log.debug("Policy Service is missing in DamlMessagePolicyMediator : adding Listener ");
          }
          ServiceAvailableListener psal= new ServiceAvailableListener() {
              public void serviceAvailable(final ServiceAvailableEvent ae) {
                if (ae.getService().equals(PolicyService.class)) {
                  if (_log.isDebugEnabled()) {
                    _log.debug("Received policy service call back ");
                  }
                  _policyService = (PolicyService)
                    AccessController.doPrivileged(new PrivilegedAction() {
                        public Object run() {
                          return ae.getServiceBroker().getService(OwlMessagePolicyMediator.this, PolicyService.class, null);
                        }
                      });
                  if (_policyService != null) {
                    if (_log.isDebugEnabled()) {
                      _log.debug("Policy  Service Discovered Daml Policy Mediator ");
                    }
                    registerMediator();
                    ae.getServiceBroker().removeServiceListener(this);
                  }
                }
              }
            };
        }
        else {
          final ServiceBroker sbf= _sb; 
          _policyService = (PolicyService)
            AccessController.doPrivileged(new PrivilegedAction() {
                public Object run() {
                  return sbf.getService(OwlMessagePolicyMediator.this, PolicyService.class, null);
                }});
          registerMediator();
        }
        _log.debug("Object Hash = " + hashCode());
      } catch (Throwable th) {
        _log.error("Exception in message node enforcer init",
                   th);
      }
      AgentIdentificationService ais= (AgentIdentificationService)_sb.getService(this, AgentIdentificationService.class,null);
      if(ais!=null){
        agentAddress = ais.getMessageAddress();
      }
    }
  
  public void registerMediator(){
    //if(agentAddress!=null){
    _policyService.registerMediator(this);
    registerEnforcer();
    /*}
      else {
      if(_log.isDebugEnabled()){
      _log.debug("In register mediator messageaddress is null ");
      }
      ServiceAvailableListener aisal= new ServiceAvailableListener() {
      public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(AgentIdentificationService.class)) {
      if (_log.isDebugEnabled()) {
      _log.debug("Received AgentIdentificationService service call back ");
      }
      AgentIdentificationService ais = (AgentIdentificationService) ae.getServiceBroker().
      getService(this, AgentIdentificationService.class, null);
      if (ais != null) {
      if (_log.isDebugEnabled()) {
      _log.debug("AgentIdentificationService discovery Daml Policy Mediator ");
      }
      agentAddress = ais.getMessageAddress();
      registerMediator();
      ae.getServiceBroker().removeServiceListener(this);
      }
      }
      }
      };
      }*/
  }

  /**
   * This method registers the enforcer to the guard and sets up
   * needed variables (such as the service broker and the logging
   * service). 
   *
   * This code used to be in the class 
   *   org.cougaar.core.security.policy.GuardRegistration
   * from securityservices.  I have modified the registerEnforcer
   * call a little.
   */
  public void registerEnforcer() throws RuntimeException
    {
      if (!_sb.hasService(EnforcerManagerService.class)) {
        if (_log.isWarnEnabled()) {
          _log.warn("Guard not available. ULMessageNodeEnforcer running without policy");
        }
        throw new RuntimeException("Guard service is not registered");
      }

      _guard = 
        (EnforcerManagerService)
        _sb.getService(this, EnforcerManagerService.class, null);
      if (_guard == null) {
        if (_log.isWarnEnabled()) {
          _log.warn("No guard registration. ULMessageNodeEnforcer running without policy");
        }
        throw new RuntimeException("No guard registration. ULMessageNodeEnforcer running without policy");
      }
      if (!_guard.registerEnforcer(this, _enforcedActionType, _agents)) {
        _sb.releaseService(this, EnforcerManagerService.class, _guard);
        if (_log.isWarnEnabled()) {
          _log.warn("Could not register with the Enforcer Manager Service");
        }
        throw new RuntimeException("Cannot register with Enforcer Manager Service");
      }
      //    bigloop();
    }


  /*
   * Testing 1 2 3
   */

  private void testIsActionAuthorized(PrintWriter out, 
                                      String sender,
                                      String receiver, 
                                      String verb)
    {
      out.print("<p>Is " + sender + " allowed to send " + verb +
                " messages to " + receiver + "?</p>");
      if (isActionAuthorized(sender, 
                             // "##" + 
                             receiver, verb)) {
        out.print("<p><font color=green>yes</font></p>");
      } else {
        out.print("<p><font color=red>no</font></p>");
      }
    }

  /**
   * This is a very simple pre-canned test.  It is called though a
   * servlet that has an html context given by the PrinterWriter out.
   */
  public void testEnforcer(PrintWriter out, List agents) 
    throws IOException, UnknownConceptException
    {
      out.print("<p><b>Message Mediation Check</b></p>");
      for (Iterator agentIt = agents.iterator();
           agentIt.hasNext();) {
        String sender    = (String) agentIt.next();
        for (Iterator agentItInner = agents.iterator();
             agentItInner.hasNext();) {
          String receiver  = (String) agentItInner.next();

          out.print("<b><p>Authorization check</p></b>");
          out.print("<p>Allowed cipher suites from " + sender
                    + " to " + receiver + "</p>");
          CipherSuite suites = getAllowedCipherSuites(sender,
                                                      // "##" + 
                                                      receiver);
          if (suites == null) {
            out.print("<p>None</p>");
          } else {
            Iterator iter = suites.getSymmetric().iterator();
            out.println("<p>Symmetric Algorithms:<ul>");
            while (iter.hasNext()) {
              out.println("<li> " + iter.next());
            }
            out.println("</ul><p>Asymmetric Algorithms:<ul>");
            iter = suites.getAsymmetric().iterator();
            while (iter.hasNext()) {
              out.println("<li> " + iter.next());
            }
            out.println("</ul><p>Signature Algorithms:<ul>");
            iter = suites.getSignature().iterator();
            while (iter.hasNext()) {
              out.println("<li> " + iter.next());
            }
            out.println("</ul>");
          }
          for (Iterator verbsIt = 
                 HardWired.readDamlDecls("Ontology-EntityInstances.owl", 
                                         "<ultralogEntity:ULContentValue rdf:ID=")
                 .iterator();
               verbsIt.hasNext();) {
            String verb = (String) verbsIt.next();
            testIsActionAuthorized(out, sender, receiver, verb);
          }
        }
      }
    }

  //George's interfaces...

  static boolean bigLoopRunning=false;

  /*
    private void bigloop()
    {
    if (!bigLoopRunning) {
    bigLoopRunning=true;
    (new Thread() {
    public void run() {
    int i = 0;
    System.out.println("Starting infinite mediation loop");
    while (true) {
    String sender = "EnclaveOnePolicyDomainManager";
    String receiver = "EnclaveOneWorkerNode";
    boolean auth = isActionAuthorized(sender,
    receiver,
    null);
    if (!auth && _log.isDebugEnabled()) {
    _log.debug("Communication not allowed");
    }
    getAllowedCipherSuites(sender, receiver);
    if (i++ % 10000 == 0) {
    System.out.println("\n" + i + " iterations of the "
    + "communications mediation loop");
    }
    }
    }
    }).start();
    }
    }
  */
  
  /**
   * This function determines if an action is authorized.  
   *
   * At the point that this query is made, the caller does not have
   * complete information about the call that is about to be
   * authorized - it does not yet know the crypto suite that will be
   * used.  However, if this call passes there will be a crypto
   * suite that will work when we get to that point.
   *
   * @param sender - a String representing the agent sending the
   * message.
   *
   * @param receiver - a String representing the agent receiving the
   * message. 
   * 
   * @param verb - a String representing the verb in the message.
   */
  public boolean isActionAuthorized(String sender,
                                    String receiver,
                                    String verb)
    {
      if (_log.isDebugEnabled()) {
        _log.debug("Called isActionAuthorized for " + sender + " to " +
                   receiver + " with verb " + verb);
        if (verb != null) {
          //        System.out.println("Found a verb!!! (" + verb + ")");
        }
      }
      String kaosVerb = VerbBuilder.kaosVerbFromVerb(verb);
      if (_log.isDebugEnabled()) {
        _log.debug("Verb has been Damlized and has become " + kaosVerb);
      }

      Set targets = new HashSet();
      targets.add(new TargetInstanceDescription(ActionConcepts.hasDestination(), 
                                                ULOntologyNames.agentPrefix + receiver));
      ActionInstanceDescription action = 
        new ActionInstanceDescription(_enforcedActionType,
                                      ULOntologyNames.agentPrefix + sender,
                                      targets);
      boolean allowed = false;
      Set verbs = null;
      try {
        verbs = _guard.getAllowableValuesForActionProperty(
          UltralogActionConcepts.hasSubject(),
          action,
          VerbBuilder.hasSubjectValues(),
          false);
        allowed  = ((verbs != null) && verbs.contains(kaosVerb));
      } catch (ServiceFailure sf) {
        if (_log.isErrorEnabled()) {
          _log.error("This shouldn't happen", sf);
        }
        allowed=false;
      }
      if (!allowed & _log.isErrorEnabled()) {
        _log.error("Verb not allowed - permission denied");
        _log.error("AID = " + action);
        _log.error("Verb = " + kaosVerb);
        _log.error("Allowed verbs = " + verbs);
      }
      _log.debug("end of isactionauthorized: kaosverb = " + kaosVerb);
      _log.debug("end of isactionauthorized: verbs = " + verbs);

      return allowed;
    }

  /**
   * This function determines the CipherSuite to use in the message.  For 
   * now it returns a set of CipherSuites but this is probably not
   * realistic and will change. 
   *
   * At the point this query is made, the caller has forgotten the verb 
   * that was used in the message and needs to determine the cipher suite 
   * to use.
   */
  public CipherSuite getAllowedCipherSuites(String sender,
                                            String receiver) {
    if (_log.isDebugEnabled()) {
      _log.debug("Called getAllowedCipherSuites for " + sender + " to " +
                 receiver);
    }
    Set targets = new HashSet();
    targets.add(new TargetInstanceDescription(ActionConcepts.hasDestination(), 
                                              ULOntologyNames.agentPrefix 
                                              + receiver));
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    ULOntologyNames.agentPrefix + sender,
                                    targets);
    Set ciphers = null;
    try {
      ciphers = 
        _guard.getAllowableValuesForActionProperty(
          UltralogActionConcepts.usedProtectionLevel(),
          action,
          _csm.usedProtectionLevelValues(),
          false);
    } catch (ServiceFailure sf) {
      if (_log.isErrorEnabled()) {
        _log.error("This shouldn't happen",  sf);
      }
      return _csm.ulCiphersFromKAoSProtectionLevel(new HashSet());
    }
    if (_log.isDebugEnabled()) {
      for (Iterator ciphersIt = ciphers.iterator(); ciphersIt.hasNext();) {
        String cipher = (String) ciphersIt.next();
        _log.debug("Allowed cipher = " + cipher);
      }
    }
    return _csm.ulCiphersFromKAoSProtectionLevel(ciphers);
  }

  /**
   * Listens for the community service
   */
  private class CommunityServiceListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(CommunityService.class)) {
        _communityService = (CommunityService) ae.getServiceBroker().
          getService(this, CommunityService.class, null);
        if (_communityService != null) {
          if (_log.isDebugEnabled()) {
            _log.debug("Community Service Discovered");
            _log.debug("Community = " + _communityService);
            _log.debug("Object Hash = " + hashCode());
          }
          ae.getServiceBroker().removeServiceListener(this);
        }
      }
    }
  }

  /* (non-Javadoc)
   * @see org.cougaar.core.security.policy.mediator.PolicyMediator#checkPermision(java.security.Permission)
   */
  public boolean checkPermision( Permission permission ) {
    if(_log.isDebugEnabled()){
      _log.debug("CheckPermission of Damal Policy mediator called ");
    }
    boolean allowed = false;
    Object o= (Object)permission ;
    if(o instanceof MessageAccessPermission){
      MessageAccessPermission maccessp= (MessageAccessPermission)o;
      allowed = this.isActionAuthorized(maccessp.getSource(),maccessp.getTarget(),maccessp.getVerb());
    }
    else{
      if(_log.isDebugEnabled()){
        _log.debug("Permission object is not instance of MessageAccessPermission");
      }
    }
    return allowed;
  }
}
