/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.enforcers;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.enforcers.util.CipherSuite;
import org.cougaar.core.security.policy.enforcers.util.HardWired;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;
import safe.guard.NodeGuard;

/**
 * This class is responsible for enforcing policy for Ultralog messages.
 */
public class ULMessageNodeEnforcer
    implements NodeEnforcer
{
  private ServiceBroker _sb;
  protected LoggingService _log;
  private CommunityService _communityService;

  private final String _enforcedActionType 
    = kaos.ontology.jena.ActionConcepts._EncryptedCommunicationAction_;
  private final String _verbGetLogSupport = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "GetLogSupport";
  private final String _verbGetWater = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "GetWater";

  private List                   _agents;
  private EnforcerManagerService _guard;

  /**
   * This returns a list of the action classes that this controls, 
   * consisting of CommunicationActions for this enforcer.
   */
  public Vector getControlledActionClasses()
  {
    Vector result = new Vector();
    result.add(_enforcedActionType);
    result.add(kaos.ontology.jena.ActionConcepts._CommunicationAction_);
    return result;
  }

  /**
   * Returns the name of the enforcer.
   */
  public String getName() { return "UL Messaging Enforcer"; }


  /**
   * This function initializes the ULMessageNodeEnforcer by providing it
   * with a service broker and the names of the agent it does enforcement
   * for. This agent thing is a temporary hack - it is not clear how the
   * association of agents and enforcers will take place.
   */
  public ULMessageNodeEnforcer(ServiceBroker sb, List agents)
  {
    try {
      // FIXME!!
      _sb = sb;
      _agents=agents;
      _log = (LoggingService) 
        _sb.getService(this, LoggingService.class, null);
      HardWired.setServiceBroker(sb);
      _log.debug("Creating Community Service Proxy");
      if (!_sb.hasService(CommunityService.class)) {
        _log.debug("Community service is missing: adding listener");
        _sb.addServiceListener(new CommunityServiceListener());
      } else {
        _communityService = (CommunityService) 
          _sb.getService(this, CommunityService.class, null);
        if (_communityService == null) {
          _log.debug("Community service is missing");
        }
        _log.debug("Community Service Created");
        _log.debug("Community = " + _communityService);
      }
      _log.debug("Object Hash = " + hashCode());
    } catch (Throwable th) {
      _log.error("Exception in message node enforcer init",
                 th);
    }
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
      _log.fatal("Guard service is not registered");
      throw new RuntimeException("Guard service is not registered");
    }

    _guard = 
      (EnforcerManagerService)
      _sb.getService(this, EnforcerManagerService.class, null);
    if (_guard == null) {
      _log.fatal("Cannot continue without guard", new Throwable());
      throw new RuntimeException("Cannot continue without guard");
    }
    if (!_guard.registerEnforcer(this, _enforcedActionType, _agents)) {
      _sb.releaseService(this, EnforcerManagerService.class, _guard);
      _log.fatal("Could not register with the Enforcer Manager Service");
      throw new RuntimeException("Cannot register with Enforcer Manager Service");
    }
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
        if (suites == null || !suites.isCipherAvailable()) { 
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
               HardWired.readDamlDecls("Ontology-EntityInstances.daml", 
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
    String kaosVerb = HardWired.kaosVerbFromVerb(verb);
    if (_log.isDebugEnabled()) {
      _log.debug("Verb has been Damlized and has become " + kaosVerb);
    }

    Set targets = new HashSet();
    targets.add(new TargetInstanceDescription
                (kaos.ontology.jena.ActionConcepts._hasDestination_, 
                 receiver));
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    sender,
                                    targets);
    Set verbs = 
      _guard.getAllowableValuesForActionProperty(
                      org.cougaar.core.security.policy.enforcers.ontology.jena.
                      UltralogActionConcepts._hasSubject_,
                      action,
                      HardWired.hasSubjectValues,
                      false);
    if (verbs == null) { return false; }
    else { 
      _log.debug("end of isactionauthorized: kaosverb = " + kaosVerb);
      _log.debug("end of isactionauthorized: verbs = " + verbs);
      return verbs.contains(kaosVerb); 
    }
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
    targets.add(new TargetInstanceDescription
                (kaos.ontology.jena.ActionConcepts._hasDestination_, 
                 receiver));
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    sender,
                                    targets);
    Set ciphers = 
      _guard.getAllowableValuesForActionProperty(
                   org.cougaar.core.security.policy.enforcers.ontology.jena.
                   UltralogActionConcepts._usedProtectionLevel_,
                   action,
                   HardWired.usedProtectionLevelValues,
                   false);
    if (_log.isDebugEnabled()) {
      for (Iterator ciphersIt = ciphers.iterator(); ciphersIt.hasNext();) {
        String cipher = (String) ciphersIt.next();
        _log.debug("Allowed cipher = " + cipher);
      }
    }
    return HardWired.ulCiphersFromKAoSProtectionLevel(ciphers);
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
}
