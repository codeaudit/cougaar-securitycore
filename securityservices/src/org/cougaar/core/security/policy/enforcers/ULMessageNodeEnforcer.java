package org.cougaar.core.security.policy.enforcers;

import org.cougaar.core.security.policy.enforcers.ontology.*;
import org.cougaar.core.security.policy.enforcers.util.CypherSuite;
import org.cougaar.core.security.policy.enforcers.util.HardWired;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

import kaos.core.util.AttributeMsg;
import kaos.core.util.SubjectListedPolicyMsg;
import kaos.ontology.jena.*;
import kaos.ontology.matching.*;
import kaos.policy.information.KAoSProperty;
import kaos.policy.information.PolicyInformation;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.ldm.policy.Policy;
import org.cougaar.planning.ldm.policy.RuleParameter;
import org.cougaar.core.service.community.CommunityService;

// KAoS policy management
import kaos.ontology.management.UnknownConceptException;
import kaos.ontology.repository.ActionInstanceDescription;
import kaos.ontology.repository.TargetInstanceDescription;
import kaos.policy.guard.PolicyDistributor;

import safe.enforcer.AgentEnforcer;
import safe.enforcer.NodeEnforcer;
import safe.guard.EnforcerManagerService;
import safe.guard.NodeGuard;
import safe.ontology.jena.UltralogActionConcepts;

/**
 * This class is responsible for enforcing policy for Ultralog messages.
 */
public class ULMessageNodeEnforcer
    implements NodeEnforcer, PolicyDistributor
{
  private ServiceBroker _sb;
  protected LoggingService _log;
  private CommunityService _communityService;
  private SemanticMatcherFactory _semFactory;

  private final String _enforcedActionType 
    = ActionConcepts._EncryptedCommunicationAction_;
  private final String _verbGetLogSupport = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "GetLogSupport";
  private final String _verbGetWater = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "GetWater";

  private List      _agents;
  private NodeGuard _guard;

  /**
   * This returns a list of the action classes that this controls, 
   * consisting of CommunicationActions for this enforcer.
   */
  public Vector getControlledActionClasses()
  {
    Vector result = new Vector();
    result.add(_enforcedActionType);
    result.add(ActionConcepts._CommunicationAction_);
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
      HardWired.setServiceBroker(sb);
      _sb = sb;
      _agents=agents;
      _log = (LoggingService) 
        _sb.getService(this, LoggingService.class, null);
      _log.debug("Creating Community Service Proxy");
      if (!_sb.hasService(CommunityService.class)) {
        _log.fatal("Community service is missing");
      }
      _communityService = 
        (CommunityService) _sb.getService(this, CommunityService.class, null);
      if (_communityService == null) {
        _log.debug("Community service is missing");
      }
      _log.debug("Community Service Created");
      _log.debug("Community = " + _communityService);
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

    EnforcerManagerService _enfMgr = 
      (EnforcerManagerService)
      _sb.getService(this, EnforcerManagerService.class, null);
    if (_enfMgr == null) {
      _log.fatal("Cannot continue without guard", new Throwable());
      throw new RuntimeException("Cannot continue without guard");
    }
    if (!_enfMgr.registerEnforcer(this, _enforcedActionType, _agents)) {
      _sb.releaseService(this, EnforcerManagerService.class, _enfMgr);
      _log.fatal("Could not register with the Enforcer Manager Service");
      throw new RuntimeException("Cannot register with Enforcer Manager Service");
    }
    if (_enfMgr instanceof NodeGuard) {
      _guard = (NodeGuard) _enfMgr;
    } else { 
      _sb.releaseService(this, EnforcerManagerService.class, _enfMgr);
      throw new RuntimeException("Cannot get guard");
    }
  }


  /**
   * This method will allow the enforcer to receive policy updates.
   */
  public void receivePolicyUpdate(String updateType, List policies)
  {
    _log.debug("ULMessageNodeEnforcer:-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    _log.debug("ULMessageNodeEnforcer:This dummy got the message (err... policy)");
    Iterator policyIterator = policies.iterator();
    while (policyIterator.hasNext()) {
      Object policyObject = policyIterator.next();
      _log.debug("ULMessageNodeEnforcer:---------A Policy--------------");
      _log.debug("ULMessageNodeEnforcer:Update type = " + updateType);
      if (!(policyObject instanceof SubjectListedPolicyMsg)) {
        _log.debug("ULMessageNodeEnforcer:.ULMessageNodeEnforcer:Don't handle this type of message");
        return;
      }
      SubjectListedPolicyMsg policy = (SubjectListedPolicyMsg) policyObject;
      Iterator subjectIterator 
        = policy.getApplicableSubjectIDs().iterator();
      while (subjectIterator.hasNext()) {
        _log.debug("ULMessageNodeEnforcer:Subject = " + subjectIterator.next());
      }
      Iterator attributeIterator
        = policy.getAttributes().iterator();
      while (attributeIterator.hasNext()) {
        AttributeMsg attribute
          = (AttributeMsg) attributeIterator.next();
        if (attribute.getName()
            .equals(AttributeMsg.POLICY_INFORMATION)) {
          PolicyInformation policyInfo
            = (PolicyInformation) attribute.getValue();
          _log.debug("ULMessageNodeEnforcer:Modality = " + 
                     policyInfo.getModality());
          _log.debug("ULMessageNodeEnforcer:Priority = " +
                     policyInfo.getPriority());
          for (Enumeration properties 
                 = policyInfo.getAllProperties();
               properties.hasMoreElements();) {
            KAoSProperty property = 
              (KAoSProperty) properties.nextElement();
            _log.debug("ULMessageNodeEnforcer:KAoS property name = "
                       + property.getPropertyName());
            _log.debug("ULMessageNodeEnforcer:KAoS class name = " 
                       + property.getClassName());
            Iterator instanceIt 
              = property.getAllInstances().iterator();
            while (instanceIt.hasNext()) {
              _log.debug("ULMessageNodeEnforcer:Instance = "
                         + instanceIt.next());
            }
            _log.debug("ULMessageNodeEnforcer:Complement? " + 
                       property.isComplement());
          }
        } else {
          _log.debug("ULMessageNodeEnforcer:--------------Name/Value----------");
          _log.debug("ULMessageNodeEnforcer:Name = " +  attribute.getName()
                     + " with type " + 
                     attribute.getName()
                     .getClass().toString());
          _log.debug("ULMessageNodeEnforcer:Value = " + attribute.getValue()
                     + " with type "
                     + attribute.getValue()
                     .getClass().toString());
          _log.debug("ULMessageNodeEnforcer:Selected = " + attribute.isSelected());
        }
      }
    }
    _log.debug("ULMessageNodeEnforcer:-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-");
  }


  /*
   * Testing 1 2 3
   */

  private void testIsActionAuthorized(PrintWriter out, 
                                      String sender,
                                      String receiver, 
                                      String verb)
  {
    out.print("<p><b>IsActionAuthorized Check</b></p>");
    out.print("<p>Is " + sender + " allowed to send " + verb +
              " messages to " + receiver + "?</p>");
    if (isActionAuthorized(sender, 
                           // "##" + 
                           receiver, verb)) {
      out.print("<p>yes</p>");
    } else {
      out.print("<p>no</p>");
    }
  }

  public void testTiming(PrintWriter out)
  {
    String sender   = (String) HardWired.agents[0];
    String receiver = (String) HardWired.agents[0];
    String verb     = "GetLogSupport";

    out.print("<p><b>Timing Check</b></p>");
    out.print("<p>Timing the two mediation calls required to determine " +
              "if and how to send a " + verb + " message from " + 
              sender + " to " + receiver + ".</p>");
    boolean allowed = false;
    Set     suites  = null;
    int     count   = 2000;
    long start = System.currentTimeMillis();
    for (int i = 0; i < count; i++) {
      suites  = getAllowedCypherSuites(sender,
                                       // "##" + 
                                       receiver);       
      allowed = isActionAuthorized(sender, 
                                   // "##" + 
                                   receiver, verb);
    }
    long duration = System.currentTimeMillis() - start;
    out.print("<p>" + count + " calls mediated in " 
              + duration + " milliseconds.</p>");
    out.print("<p>Last call returned the following results: ");
    out.print("<p>Allowed cypher suites:</p>");
    if (suites == null || suites.size() ==0) { 
      out.print("<p>None</p>");
    } else {
      int counter = 0;
      for (Iterator suitesIt=suites.iterator(); 
           suitesIt.hasNext();) {
        CypherSuite c = (CypherSuite) suitesIt.next();
        out.print("<p>Suite " + (counter++) + ":<ul>");
        out.print("<li>Symmetric = " + c.getSymmetric());
        out.print("<li>Asymmetric = " + c.getAsymmetric());
        out.print("<li>Checksum = " + c.getChecksum());
        out.print("</ul>");
      }
    }
    out.print("<p>Message ");
    if (allowed) { out.print("allowed</p>"); } 
    else { out.print("not allowed</p>"); }
  }


  /**
   * This is a very simple pre-canned test.  It is called though a
   * servlet that has an html context given by the PrinterWriter out.
   */
  public void testEnforcer(PrintWriter out) 
    throws IOException, UnknownConceptException
  {
    out.print("<p><b>Semantic Matchers Check</b></p>");
    for (int i = 0; i < HardWired.agents.length; i++) {
      for (int j = 0; j < HardWired.agents.length; j++) {
        String sender    = HardWired.agents[i];
        String receiver  = HardWired.agents[j];
        out.print("<p>Allowed cypher suites from " + sender
                  + " to " + receiver + "</p>");
        Set suites = getAllowedCypherSuites(sender,
                                            // "##" + 
                                            receiver);
        if (suites == null || suites.size() ==0) { 
          out.print("<p>None</p>");
        } else {
          int counter = 0;
          for (Iterator suitesIt=suites.iterator(); 
               suitesIt.hasNext();) {
            CypherSuite c = (CypherSuite) suitesIt.next();
            out.print("<p>Suite " + (counter++) + ":<ul>");
            out.print("<li>Symmetric = " + c.getSymmetric());
            out.print("<li>Asymmetric = " + c.getAsymmetric());
            out.print("<li>Checksum = " + c.getChecksum());
            out.print("</ul>");
          }
        }
        testIsActionAuthorized(out, sender, receiver, "GetWater");
        testIsActionAuthorized(out, sender, receiver, "GetLogSupport");
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
    }
    String kaosVerb = HardWired.kaosVerbFromVerb(verb);

    Set targets = new HashSet();
    targets.add(new TargetInstanceDescription
                (ActionConcepts._hasDestination_, 
                 receiver));
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    sender,
                                    targets);
    Set verbs = 
      _guard.getAllowableValuesForActionSingleTim(
                                   UltralogActionConcepts._hasSubject_,
                                   action,
                                   HardWired.hasSubjectValues);
    if (verbs == null) { return false; }
    else { 
      _log.debug("end of isactionauthorized: kaosverb = " + kaosVerb);
      _log.debug("end of isactionauthorized: verbs = " + verbs);
      return verbs.contains(kaosVerb); 
    }
  }

  /**
   * This function determines the CypherSuite to use in the message.  For 
   * now it returns a set of CypherSuites but this is probably not
   * realistic and will change. 
   *
   * At the point this query is made, the caller has forgotten the verb 
   * that was used in the message and needs to determine the cypher suite 
   * to use.
   */
  public Set getAllowedCypherSuites(String sender,
                             String receiver) {
    if (_log.isDebugEnabled()) {
      _log.debug("Called getAllowedCypherSuites for " + sender + " to " +
                 receiver);
    }
    Set targets = new HashSet();
    targets.add(new TargetInstanceDescription
                (ActionConcepts._hasDestination_, 
                 receiver));
    ActionInstanceDescription action = 
      new ActionInstanceDescription(_enforcedActionType,
                                    sender,
                                    targets);
    Set ciphers = 
      _guard.getAllowableValuesForActionSingleTim(
                   UltralogActionConcepts._usedProtectionLevel_,
                   action,
                   HardWired.usedProtectionLevelValues);
    return HardWired.ulCiphersFromKAoSProtectionLevel(ciphers);
  }

}
