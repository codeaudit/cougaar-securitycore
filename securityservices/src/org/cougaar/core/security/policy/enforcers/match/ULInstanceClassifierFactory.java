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

package org.cougaar.core.security.policy.enforcers.match;

import java.util.*;

import kaos.ontology.matching.*;
import kaos.ontology.jena.ActionConcepts;
import kaos.policy.information.KAoSProperty;

import EDU.oswego.cs.dl.util.concurrent.Semaphore;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;

import org.cougaar.core.security.policy.enforcers.ontology.ActorClassesConcepts;
import org.cougaar.core.security.policy.enforcers.util.UserDatabase;

public class ULInstanceClassifierFactory
    implements InstanceClassifierFactory
{
  private ServiceBroker _sb;
  private CommunityService _communityService;
  private HashMap _communityCache = new HashMap();
  private LoggingService _log;
  private ULActorInstanceClassifier _instClassifier;

  public ULInstanceClassifierFactory(ServiceBroker sb)
  {
    _sb               = sb;
    _instClassifier         = new  ULActorInstanceClassifier();

    // get the LoggingService
    _log = (LoggingService) _sb.getService(this,
                                           LoggingService.class,
                                           null);
    if (_log == null) {
      throw new NullPointerException("LoggingService");
    }
  }
  /**
   * Instantiate a semantic matcher for the property name.
   *
   * @param  propertyName               The String specifying the
   *                                  property, for which a matcher
   *                                  is requested.  
   *     
   * @return InstanceClassifier           an instance of the requested
   *                                   semantic matcher, or null, if
   *                                  no semantic matcher is required.
   *
   * @exception                       InstanceClassifierInitializationException
   *                                   is thrown if the
   *                                  instantiation of the matcher was not  
   *                                  successful, details will be
   *                                  provided in the exception's message. 
   */
  public  InstanceClassifier getInstance (String propertyName) 
    throws InstanceClassifierInitializationException
  {
    if (propertyName.equals(ActionConcepts._performedBy_) || 
        propertyName.equals(ActionConcepts._hasDestination_) ) {
      return _instClassifier;
    } else {
      return null;
    }
  }


  private void ensureCommunityServicePresent()
  {
    if (_communityService == null) {
      _communityService = 
        (CommunityService) _sb.getService(this, 
                                          CommunityService.class, 
                                          null);
      if (_communityService == null) {
        throw new RuntimeException("No community service");
      }
      _log.debug("ULInstanceClassifier: Community Service installed");
    }
  }

  static String removeHashChar(String s)
  {
    if (s.startsWith("#")) {
      return s.substring(1);
    }
    return s;
  }

  private class ULActorInstanceClassifier implements InstanceClassifier
  {
    private String communityPrefix = "KAoS#MembersOfDomainCommunity";
    private String personPrefix    = ActorClassesConcepts.ActorClassesDamlURL;

    public void init ()
      throws InstanceClassifierInitializationException 
    {
      return;
    }

    public boolean classify(String className, Object instance) 
      throws InstanceClassifierInitializationException
    {
      String actor = (String) instance;
      actor     = removeHashChar(actor);
      className = removeHashChar(className);
      if (className.equals(kaos.ontology.jena.ActorConcepts._Agent_)) {
        return !UserDatabase.isUser(actor);
      } else if (className.startsWith(communityPrefix)) {
        ensureCommunityServicePresent();

        String community 
          = className.substring(communityPrefix.length());
        Collection communities = getCommunitiesFromAgent(actor);

        return communities.contains(community);
      } else if (className.startsWith(personPrefix)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Dealing with a person");
        }
        String role 
          = className.substring(personPrefix.length());
        if (_log.isDebugEnabled()) {
          _log.debug("MatchSing with the role " + role);
        }
        
        if (actor.equals(UserDatabase.anybody())) {
          return true;     /* questionable */
        } else {
          Set roles = UserDatabase.getRoles(actor);
          if (_log.isDebugEnabled()) {
            _log.debug("Found roles " + roles + "for actor " + actor);
          }
          return roles.contains(role);
        }
      } else if (className.equals(kaos.ontology.jena.ActorConcepts._Person_)) {
        return UserDatabase.isUser((String) instance);
      }
      return false;
    }

    public int classify(String className, Set instances)
      throws InstanceClassifierInitializationException
    {
      if (_log.isDebugEnabled()) {
        _log.debug(".ULInstanceClassifier: Entering with classname "
                   + className + " and instances: ");
        for (Iterator instancesIt = instances.iterator();
             instancesIt.hasNext();) {
          String instance = (String) instancesIt.next();
          _log.debug(".ULInstanceClassifier: " + instance);
        }
      }
      boolean someMatch     = false;
      boolean someDontMatch = false;
      for (Iterator actorIt = instances.iterator(); 
           actorIt.hasNext();) {
        Object actor = (String) actorIt.next();
        if (classify(className, actor)) {
          _log.debug("ULInstanceClassifier: found match of " + className +
                     " and " + actor);
          someMatch = true;
        } else {
          _log.debug("ULInstanceClassifier: found non-match of " + className +
                     " and " + actor);
          someDontMatch = true;
        }
      }
      if (someMatch && someDontMatch) {
        return 1;
      } else if (someMatch) {
        return KAoSProperty._ALL_INST_PRESENT;
      } else if (someDontMatch) {
        return KAoSProperty._NO_INST_PRESENT;
      } else {
        return KAoSProperty._ALL_INST_PRESENT;
      }
    }

    private class Status
    {
      public Collection communities;
    }

    private Collection getCommunitiesFromAgent(String agent)
    {
      Collection communities  = null;
      Object     cached;

      if ((cached = _communityCache.get(agent)) == null) {
	// TODO. Resolve community membership in the policy update call.
	String comms[] = _communityService.getParentCommunities(true);
	if (comms != null) {
	  communities = new ArrayList(comms.length);
	  for (int i = 0 ; i < comms.length ; i++) {
	    communities.add(comms[i]);
	  }
	  _communityCache.put(agent, communities);
	}
      } else {
        communities = (Collection) cached;
      }
      _log.debug("Returning " + communities + " for " + agent);
      return communities;
    }
  }
}
