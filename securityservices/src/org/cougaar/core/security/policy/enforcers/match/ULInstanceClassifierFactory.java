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


package org.cougaar.core.security.policy.enforcers.match;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

import kaos.ontology.matching.InstanceClassifier;
import kaos.ontology.matching.InstanceClassifierClassCastException;
import kaos.ontology.matching.InstanceClassifierFactory;
import kaos.ontology.matching.InstanceClassifierInitializationException;
import kaos.ontology.vocabulary.ActionConcepts;
import kaos.ontology.vocabulary.ActorConcepts;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.auth.role.RoleExecutionContext;
import org.cougaar.core.security.policy.enforcers.util.UserDatabase;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActorConcepts;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Agent;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;


public class ULInstanceClassifierFactory
    implements InstanceClassifierFactory
{
  public static final String pluginPrefix 
    = ULOntologyNames.pluginsInRoleClassPrefix;

  private ServiceBroker _sb;
  private CommunityService _communityService;
  private HashMap _communityCache = new HashMap();
  private HashMap _listeners      = new HashMap();
  private LoggingService _log;
  private ULActorInstanceClassifier _instClassifier;
  private Object _csLock = new Object(); // a mutex for _communityService

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

    _communityService = (CommunityService) 
      _sb.getService(this, CommunityService.class, null);
    if (_communityService == null) {
      _sb.addServiceListener(new CommunityServiceListener());
    }

    if (_log.isDebugEnabled()) {
      _log.debug("ULInstanceClassifier factory initialized");
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
    if (_log.isDebugEnabled()) {
      _log.debug("Getting instance classifier instance for " + propertyName);
    }
    if (propertyName.equals(ActionConcepts.performedBy()) || 
        propertyName.equals(ActionConcepts.hasDestination()) ) {
      return _instClassifier;
    } else {
      return null;
    }
  }


  private void ensureCommunityServicePresent()
  {
    // wait for the community service to show up
    if (_communityService == null) {
      synchronized (_csLock) {
        while (_communityService == null) {
          try {
            _log.debug("Waiting for CommunityService to be available...");
            _csLock.wait();
            _log.debug("CommunityService is now available");
          } catch (InterruptedException e) {
            // go around again...
          }
        }
      }
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
    private String communityPrefix  = "KAoS#MembersOfDomainCommunity";
    private String personPrefix     = ULOntologyNames.personActorClassPrefix;
    private Set    _loadAgents     = new HashSet();

    public void init ()
      throws InstanceClassifierInitializationException 
    {
      if (_log.isDebugEnabled()) {
        _log.debug("Initializing the Actor Instance Classifier");
      }
      return;
    }

    public void init(String className) {
      if (_log.isDebugEnabled()) {
        _log.debug("Initializing the Actor Instance Classifier "
                   + "for the classname" + className);
      }
      if (className.startsWith(communityPrefix)) {
        ensureCommunityServicePresent();
        String community = className.substring(communityPrefix.length());
        loadAgentsInCommunity(community);
      }
    }

    public boolean classify(Object className, 
                            Object instance,
                            Object classDesc,
                            Object instDesc) 
      throws InstanceClassifierInitializationException, 
             InstanceClassifierClassCastException
    {
      if (_log.isDebugEnabled()) {
        _log.debug("Classifying + (" + className + ", " 
                                     + instance + ", " 
                                     + classDesc + ", "
                                     + instDesc + ")");
      }
      if (className instanceof String) {
        boolean ret = classify((String) className, instance);
        if (_log.isDebugEnabled()) {
          _log.debug("Returning " + ret);
        }
        return ret;
      } else {
        return false;
      }
    }

    public boolean classify(String className, Object instance) 
      throws InstanceClassifierInitializationException
    {
      if (_log.isDebugEnabled()) {
        _log.debug("Classifying actor " + instance + " against the class "
                   + className);
      }
      className = removeHashChar(className);

      /*
       *    Everybody is an actor
       */
      if (className.equals(ActorConcepts.Actor())) {
        _log.debug("Every actor matches Actor");
        return true;
      }

      /*
       * Classifying plugins (for blackboard access control at the moment)
       */
      if (className.equals(UltralogActorConcepts.UltralogPlugins())) {
        if (_log.isDebugEnabled()) {
          _log.debug("Is the instance an execution context for a plugin?");
          _log.debug("Class of instance = " + instance.getClass());
        }
        return (instance instanceof RoleExecutionContext);
      }
      if (_log.isDebugEnabled()) {
        _log.debug("pluginPrefix = " + pluginPrefix);
      }
      if (className.startsWith(pluginPrefix)) {
        if (_log.isDebugEnabled()) {
          _log.debug("we are classifying some type of plugin");
        }
        if (instance instanceof RoleExecutionContext) {
          String shortRoleName 
            = className.substring(pluginPrefix.length());
          if (_log.isDebugEnabled()) {
            _log.debug("Taking a look at the RoleExecutionContext - "
                       + "looking at short role name " + shortRoleName);
          }
          String damlRoleName = ULOntologyNames.pluginsInRoleClassPrefix + shortRoleName;

          if (_log.isDebugEnabled()) {
            _log.debug("damlRoleName = " + damlRoleName);
          }
          RoleExecutionContext rec = (RoleExecutionContext) instance;
          return rec.hasComponentRole(damlRoleName) 
            || rec.hasAgentRole(damlRoleName)
            || rec.hasUserRole(damlRoleName);
        } else { 
          if (_log.isDebugEnabled()) {
            _log.debug("But the instance is not a plugin");
            _log.debug("Instance Class = " + instance.getClass());
          }
          return false; 
        }
      }
      /*
       * This is the end of the cases where instance is not a String
       */
      if (! (instance instanceof String)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Not a match because the instance is not a String");
        }
        return false;
      }

      /*
       * Classifying Agents or People
       */
      String actor = (String) instance;
      if (_log.isDebugEnabled()) {
        _log.debug("Classifying agents  or people");
      }
      actor     = removeHashChar(actor);
      if (className.equals(ActorConcepts.Agent())) {
        if (_log.isDebugEnabled()) {
          _log.debug("Looking for agents");
        }
        return !UserDatabase.isUser(actor);
      } else if (className.startsWith(communityPrefix)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Here's to hoping you aren't here...");
        }        
        ensureCommunityServicePresent();

        String community 
          = className.substring(communityPrefix.length());

        return isAgentInCommunity(community, actor);

        /*
         * Classifying Person(s)
         */
      } else if (className.startsWith(personPrefix)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Dealing with a person");
        }
        String role = className.substring(personPrefix.length());
        if (_log.isDebugEnabled()) {
          _log.debug("Matching with the role " + role);
        }
        
        Set roles = UserDatabase.getRoles(actor);
        if (_log.isDebugEnabled()) {
          _log.debug("Found roles " + roles + "for actor " + actor);
        }
        return roles.contains(role);
      } else if (className.equals(ActorConcepts.Person())) {
        return UserDatabase.isUser((String) instance);
      }
      return false;
    }


    private class Status
    {
      public Collection communities;
    }

    private void loadAgentsInCommunity(String community) {
      LoadAgentsListener listener = new LoadAgentsListener(community);
      Collection c = _communityService.searchCommunity(community, "*", true,
                                                       Community.AGENTS_ONLY,
                                                       listener);
      if (c != null) {
        setCommunityAgents(community, c);
        return;
      }
      boolean block = false;
      synchronized (_loadAgents) {
        _loadAgents.add(listener);
        if (_loadAgents.size() == 1) {
          // we have to block, there are no others waiting...
          do {
            try {
              _loadAgents.wait();
            } catch (InterruptedException e) {
            }
          } while (!_loadAgents.isEmpty());
        }
      }
    }

    private void setCommunityAgents(String community, Collection c) {
      synchronized (_communityCache) {
        Set agents = (Set) _communityCache.get(community);
        if (agents == null) {
          agents = new HashSet();
          _communityCache.put(community, agents);
        } else {
          agents.clear();
        }
        Iterator iter = c.iterator();
        while (iter.hasNext()) {
          Agent agent = (Agent) iter.next();
          agents.add(agent.getName());
        }
      }
      addCommunityListener(community);
    }

    private synchronized void addCommunityListener(String community) {
      if (!_listeners.containsKey(community)) {
        CommunityWatcher listener = new CommunityWatcher(community);
        _communityService.addListener(listener);
        _listeners.put(community, listener);
      }
    }

    private synchronized void removeCommunityListener(String community) {
      CommunityWatcher listener = (CommunityWatcher)
        _listeners.remove(community);
      if (listener != null) {
        _communityService.removeListener(listener);
      }
    }

    private boolean isAgentInCommunity(String community, String agent) {
      synchronized (_communityCache) {
        Set agents = (Set) _communityCache.get(community);
        if (agents == null) {
          return false;
        }
        return agents.contains(agent);
      }
    }

    private class LoadAgentsListener implements CommunityResponseListener {
      private Collection _response = null;
      private String     _community;

      public LoadAgentsListener(String community) {
        _community = community;
      }

      public synchronized void getResponse(CommunityResponse response) {
        if (response.getStatus() != CommunityResponse.SUCCESS) {
          _log.warn("Problem loading community response: " + 
                    response.getStatusAsString());
          _response = new LinkedList();
        } else {
          _response = (Collection) response.getContent();
        }
        setCommunityAgents(_community, _response);
        synchronized (_loadAgents) {
          _loadAgents.remove(this);
          if (_loadAgents.isEmpty()) {
            _loadAgents.notifyAll();
          }
        }
      }

      public Collection getResponse() {
        return _response;
      }

      public int hashCode() {
        return _community.hashCode();
      }

      public boolean equals(Object obj) {
        if (obj instanceof LoadAgentsListener) {
          return _community.equals(((LoadAgentsListener) obj)._community);
        }
        return false;
      }
    }

    private class CommunityWatcher implements CommunityChangeListener {
      private String _community;

      public CommunityWatcher(String community) {
        _community = community;
      }

      public void communityChanged(CommunityChangeEvent event) {
        Set communitySet;
        synchronized (_communityCache) {
          communitySet = (Set) _communityCache.get(_community);
        }
        if (communitySet != null) {
          synchronized (communitySet) {
            int type = event.getType();
            if (type == CommunityChangeEvent.ADD_COMMUNITY) {
              addCommunityListener(event.getCommunityName());
            } else if (type == CommunityChangeEvent.REMOVE_COMMUNITY) {
              removeCommunityListener(event.getCommunityName());
            } 
            // type == event.ADD_ENTITY || type == event.REMOVE_ENTITY also...
            loadAgentsInCommunity(_community);
          }
        }
      }

      public String getCommunityName() {
        return _community;
      }
    }
  }



  private class CommunityServiceListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      if (ae.getService().equals(CommunityService.class)) {
        _communityService = (CommunityService) 
          ae.getServiceBroker().getService(ULInstanceClassifierFactory.this,
                                           CommunityService.class, null);
        ae.getServiceBroker().removeServiceListener(this);
        synchronized (_csLock) {
          _csLock.notifyAll();
        }
      }
    }
  }
}
