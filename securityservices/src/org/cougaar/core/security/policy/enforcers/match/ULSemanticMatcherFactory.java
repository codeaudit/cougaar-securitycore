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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.security.policy.enforcers.ontology.ActorClassesConcepts;
import org.cougaar.core.security.policy.enforcers.util.UserDatabase;

public class ULSemanticMatcherFactory 
    implements SemanticMatcherFactory
{
  private ServiceBroker _sb;
  private CommunityService _communityService;
  private HashMap _communityCache = new HashMap();
  private LoggingService _log;
  private ULActorSemanticMatcher _semMatch;

  public ULSemanticMatcherFactory(ServiceBroker sb)
  {
    _sb               = sb;
    _semMatch         = new  ULActorSemanticMatcher();

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
   * @return SemanticMatcher           an instance of the requested
   *                                   semantic matcher, or null, if
   *                                  no semantic matcher is required.
   *
   * @exception                       SemanticMatcherInitializationException
   *                                   is thrown if the
   *                                  instantiation of the matcher was not  
   *                                  successful, details will be
   *                                  provided in the exception's message. 
   */
  public  SemanticMatcher getInstance (String propertyName) 
    throws SemanticMatcherInitializationException
  {
    if (propertyName.equals(ActionConcepts._performedBy_) || 
        propertyName.equals(ActionConcepts._hasDestination_) ) {
      return _semMatch;
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
      _log.debug("ULSemanticMatcher: Community Service installed");
    }
  }

  static String removeHashChar(String s)
  {
    if (s.startsWith("#")) {
      return s.substring(1);
    }
    return s;
  }

  private class ULActorSemanticMatcher implements SemanticMatcher
  {
    private String communityPrefix = "KAoS#MembersOfDomainCommunity";
    private String personPrefix    = ActorClassesConcepts.ActorClassesDamlURL;

    public void initSemanticMatcher ()
      throws SemanticMatcherInitializationException 
    {
      return;
    }

    public boolean matchSemantically(String className, Object instance) 
      throws SemanticMatcherInitializationException
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
          _log.debug("Matching with the role " + role);
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

    public int matchSemantically(String className, Set instances)
      throws SemanticMatcherInitializationException
    {
      if (_log.isDebugEnabled()) {
        _log.debug(".ULSemanticMatcher: Entering with classname "
                   + className + " and instances: ");
        for (Iterator instancesIt = instances.iterator();
             instancesIt.hasNext();) {
          String instance = (String) instancesIt.next();
          _log.debug(".ULSemanticMatcher: " + instance);
        }
      }
      boolean someMatch     = false;
      boolean someDontMatch = false;
      for (Iterator actorIt = instances.iterator(); 
           actorIt.hasNext();) {
        Object actor = (String) actorIt.next();
        if (matchSemantically(className, actor)) {
          _log.debug("ULSemanticMatcher: found match of " + className +
                     " and " + actor);
          someMatch = true;
        } else {
          _log.debug("ULSemanticMatcher: found non-match of " + className +
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

    //      /*******************Generic Agent********************/
    //      className = removeHashChar(className);
    //      if (className.equals(kaos.ontology.jena.ActorConcepts._Agent_)) {
    //	  return KAoSProperty._ALL_INST_PRESENT;
    //      } else if (className.startsWith(communityPrefix)) {
    //        ensureCommunityServicePresent();
    //        boolean someMatch     = false;
    //        boolean someDontMatch = false;
    //
    //        String community 
    //          = className.substring(communityPrefix.length());
    //        for (Iterator agentIt = instances.iterator(); 
    //             agentIt.hasNext();) {
    //          String agent = (String) agentIt.next();
    //          agent = removeHashChar(agent);
    //
    //          Collection communities = getCommunitiesFromAgent(agent);
    //
    //          _log.debug("matchSemantically: Communities for agent, " 
    //                     + agent + " = ");
    //          for(Iterator communitiesIt = communities.iterator();
    //              communitiesIt.hasNext();) {
    //            _log.debug("Community: " + communitiesIt.next());
    //          }
    //          _log.debug("matchSemantically: contains community, "
    //                     + community + "?");
    //          if (communities.contains(community)) {
    //            _log.debug("matchSemantically: yes");
    //            someMatch = true;
    //          } else {
    //            _log.debug("matchSemantically: no");
    //            someDontMatch = true;
    //          }
    //          if (someMatch && someDontMatch) {
    //            _log.debug("matchSemantically: return partial match");
    //            return 1;  // a partial match
    //          }
    //        }
    //        // can't have both someMatch and someDontMatch
    //        _log.debug("matchSemantically: someMatch = " + someMatch);
    //        _log.debug("matchSemantically: someDontMatch = " + 
    //                   someDontMatch);
    //        if (someMatch) {
    //          return KAoSProperty._ALL_INST_PRESENT;
    //        } else if (someDontMatch) {
    //          return KAoSProperty._NO_INST_PRESENT;
    //        } else {
    //          return KAoSProperty._ALL_INST_PRESENT;
    //        }
    //      } else if ((className.startsWith(personPrefix))) {
    //        boolean someMatch     = false;
    //        boolean someDontMatch = false;
    //
    //        String policyRole
    //          = className.substring(personPrefix.length());
    //        for (Iterator personIt = instances.iterator(); 
    //             personIt.hasNext();) {
    //          String person = (String) personIt.next();
    //          person = removeHashChar(person);
    //
    //          Set userRoles = UserDatabase.getRoles(person);
    //          Set userRolesStripped = new HashSet();
    //          for (Iterator userRolesIt = userRoles.iterator();
    //               userRolesIt.hasNext();) {
    //            String userRole = (String) userRolesIt.next();
    //            
    //            userRolesStripped.add(userRole
    //                                  .substring(userRole.indexOf('\\') + 1));
    //          }
    //          if (_log.isDebugEnabled()) {
    //            _log.debug("matchSemantically: Roles for person, " 
    //                       + person + " = ");
    //            for(Iterator userRolesIt = userRolesStripped.iterator();
    //                userRolesIt.hasNext();) {
    //              _log.debug("Role: " + userRolesIt.next());
    //            }
    //            _log.debug("matchSemantically: contains role, "
    //                       + policyRole + "?");
    //          }
    //
    //          if (userRolesStripped.contains(policyRole)) {
    //            _log.debug("matchSemantically: yes");
    //            someMatch = true;
    //          } else {
    //            _log.debug("matchSemantically: no");
    //            someDontMatch = true;
    //          }
    //          if (someMatch && someDontMatch) {
    //            _log.debug("matchSemantically: return partial match");
    //            return 1;  // a partial match
    //          }
    //        }
    //        // can't have both someMatch and someDontMatch
    //        _log.debug("matchSemantically: someMatch = " + someMatch);
    //        _log.debug("matchSemantically: someDontMatch = " + 
    //                   someDontMatch);
    //        if (someMatch) {
    //          return KAoSProperty._ALL_INST_PRESENT;
    //        } else if (someDontMatch) {
    //          return KAoSProperty._NO_INST_PRESENT;
    //        } else {
    //          return KAoSProperty._ALL_INST_PRESENT;
    //        }      
    //      } else if (className.equals(kaos.ontology.jena.ActorConcepts._Person_)) {
    //        boolean someMatch     = false;
    //        boolean someDontMatch = false;
    //
    //        for (Iterator personIt = instances.iterator(); 
    //             personIt.hasNext();) {
    //          String person = (String) personIt.next();
    //          person = removeHashChar(person);
    //
    //          if (UserDatabase.isUser(person)) {
    //            _log.debug("matchSemantically: yes");
    //            someMatch = true;
    //          } else {
    //            _log.debug("matchSemantically: no");
    //            someDontMatch = true;
    //          }
    //          if (someMatch && someDontMatch) {
    //            _log.debug("matchSemantically: return partial match");
    //            return 1;  // a partial match
    //          }
    //        }
    //        // can't have both someMatch and someDontMatch
    //        _log.debug("matchSemantically: someMatch = " + someMatch);
    //        _log.debug("matchSemantically: someDontMatch = " + 
    //                   someDontMatch);
    //        if (someMatch) {
    //          return KAoSProperty._ALL_INST_PRESENT;
    //        } else if (someDontMatch) {
    //          return KAoSProperty._NO_INST_PRESENT;
    //        } else {
    //          return KAoSProperty._ALL_INST_PRESENT;
    //        }      
    //      } else {
    //        return KAoSProperty._NO_INST_PRESENT;
    //      }

    private Collection getCommunitiesFromAgent(String agent)
    {
      Collection communities;
      Object     cached;

      if ((cached = _communityCache.get(agent)) == null) {
        communities = _communityService.listParentCommunities(agent);
        if (communities == null) {
          communities = new HashSet();
        }
        _communityCache.put(agent, communities);
      } else {
        communities = (Collection) cached;
      }
      _log.debug("Returning " + communities + " for " + agent);
      return communities;
    }
  }
}
