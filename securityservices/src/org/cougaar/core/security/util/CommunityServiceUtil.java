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

package org.cougaar.core.security.util;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import org.cougaar.community.manager.Request;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.Agent;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.thread.Schedulable;

import EDU.oswego.cs.dl.util.concurrent.Semaphore;

/**
 * Utility methods for the CommunityService
 */
public class CommunityServiceUtil {
  private CommunityService _cs;
  private LoggingService _log;
  private ServiceBroker _sb;
  private ThreadService _threadService;
  private String        _agent;
 
  /**
   * Number of seconds to wait until we check whether we have
   * a response from the community service. It's hard to know
   * when we should have a response. This value is used only
   * to help with debugging, e.g. if we timeout, then we dump
   * a warning in the logger.
   */
  public static final long COMMUNITY_WARNING_TIMEOUT = 300 * 1000;

  public static final String SECURITY_COMMUNITY_TYPE = "Security";
  public static final String MONITORING_SECURITY_COMMUNITY_TYPE = "MnR-Security";
  public static final String MANAGER_ROLE = "Manager";
  public static final String MANAGER_ROOT = "Root";
  public static final String MEMBER_ROLE = "Member";
  private static final String ROLE_FILTER = "(Role=" + MANAGER_ROLE +")";
  private static final String ROLE_MEMBER_FILTER = "(Role=" + MEMBER_ROLE +")";
  private static final String ROOT_FILTER = "(&(Role=" + MANAGER_ROOT +")" +
  "(Role=" + MANAGER_ROLE + "))";

  
  public CommunityServiceUtil(ServiceBroker sb) {
    if(sb == null) {
      throw new IllegalArgumentException("ServiceBroker sb is null");
    }
    _sb = sb;
    _cs = (CommunityService)_sb.getService(this, CommunityService.class, null);
    _log = (LoggingService)_sb.getService(this, LoggingService.class, null);
    _threadService = (ThreadService)
      _sb.getService(this, ThreadService.class, null);
    AgentIdentificationService ais = (AgentIdentificationService)
      _sb.getService(this, AgentIdentificationService.class, null);
    _agent = ais.getMessageAddress().toAddress();
    _sb.releaseService(this, AgentIdentificationService.class, ais);
  }

  public void releaseServices() {
    _sb.releaseService(this, CommunityService.class, _cs);
    _sb.releaseService(this, LoggingService.class, _log);
    _sb.releaseService(this, ThreadService.class, _threadService);
  }

   /**
   * determine the m&r security managers for the current agent
   *
   * @return the message address of the m&r security manager
   */
  public void findMySecurityManager(String communityType,final CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug("findSecurityManager called for agent : "+_agent);
      _log.debug("Stack",new Exception());
    }
    //_log.info("findSecurityManager called for agent : "+_agent);
    /*
    CommunityServiceUtilListener myListener =
      new CommunityServiceUtilListener() {
        public void getResponse(Set communities) {
          if(_log.isDebugEnabled()) {
            _log.debug("Agent "+ _agent +
		       " Got Response in myListener of findSecurityManager :"
		       +communities);
          }
          if(!communities.isEmpty()){
          	Community comm =null;
            Iterator iter=communities.iterator();
            while(iter.hasNext()){
            	comm = (Community)iter.next();
            }
          }
          Community comm = (Community) communities.iterator().next();
          getAgentsInCommunity(comm.getName(), MANAGER_ROLE, listener,CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE);
        }
      };
      */
    if(_log.isDebugEnabled()) {
      _log.debug("calling getCommunityAgent from  findSecurityManager for agent : "+_agent);
    }
    getCommunityAgent(communityType, MANAGER_ROLE, listener);
  }


  /**
   * determine the m&r security managers for the current MnRManager agent  
   *
   * @return the message address of the m&r security manager
   */
  public void findSecurityManager(String communityType,final CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug("findSecurityManager called for agent : "+_agent);
      _log.debug("Stack",new Exception());
    }
    //_log.info("findSecurityManager called for agent : "+_agent);
    CommunityServiceUtilListener myListener =
      new CommunityServiceUtilListener() {
        public void getResponse(Set communities) {
          if(_log.isDebugEnabled()) {
            _log.debug("Agent "+ _agent +
		       " Got Response in myListener of findSecurityManager :"
		       +communities);
          }
          Community comm = (Community) communities.iterator().next();
          getAgentsInCommunity(comm.getName(), MANAGER_ROLE, listener,CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE);
        }
      };
    if(_log.isDebugEnabled()) {
      _log.debug("calling getCommunityNoRole from  findSecurityManager for agent : "+_agent);
    }
    getCommunityNoRole(communityType, MANAGER_ROLE, myListener);
  }

  public boolean isRoot(Community community) {
    Set set = community.search(ROOT_FILTER, Community.AGENTS_ONLY);
    return !set.isEmpty();
  }
  
  
  /**
   * Searches whether the agent invoking this method has a specified role
   * in a community.
   * @param community - The community where the search is performed.
   * @param role - The role that is being searched.
   * @param contains - true: searches whether the community has the role 'role'
   *                   false: searches whether the community does NOT have the role 'role'.
   * @return true if the search was successful.
   */
  public boolean hasRole(Community community, String role, boolean contains) {
    String filter = "(Role=" + role + ")";
    if (!contains) {
      filter = "(!" + filter + ")";
    }
    Set set = community.search(filter,
                               Community.AGENTS_ONLY);
    Iterator iter = set.iterator();
    while (iter.hasNext()) {
      Entity agent = (Entity) iter.next();
      if (agent.getName().equals(_agent)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns a subset of communities where the current agent has specified roles. 
   * @param communities - the collection of communities where the search is performed.
   * @param role
   * @param contains
   * @return the subset of 'communities' that satisfies the search.
   */
  public Set withRole(Collection communities, String role, boolean contains) {
    Set commSet = new HashSet();
    Iterator iter = communities.iterator();
    while (iter.hasNext()) {
      Community community = (Community) iter.next();
      if (hasRole(community, role, contains)) {
        commSet.add(community);
      }
    }
    return commSet;
  }

  /**
   * Retrieves all security communities for which this agent is a member
   */
  public void getSecurityCommunities(String communityType,CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug("getSecurityCommunities called for agent : "+_agent);
    }
    getCommunity(communityType, MEMBER_ROLE, listener);
  }
  /**
   * Retrieves all security communities for which this agent is a member
   * it will provide updates as more communities are added 
   */
  public void getSecurityCommunitiesWithUpdates(CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug("getSecurityCommunitiesWithUpdates  called for agent : "+_agent);
    }
    getCommunityWithUpdates(SECURITY_COMMUNITY_TYPE, MEMBER_ROLE, listener);
  }

  /**
   * Retrieves all communities for which this agent is a member and
   * does not have the given role.
   */
  public void getCommunityNoRole(String communityType, String notRole,
                                 CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug("getCommunityNoRole called for agent : "+_agent);
    }
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent +
		 "In getCommunityNoRole () Looking for community of type "
		 + communityType +
                 " for which " + _agent + " does not have role " + notRole);
    }
    final Runnable tt =
      new WarnThread(_agent + 
		     " searching for not role (" + notRole +
		     ") in community " +
		     "type (" + communityType + ")",
		     _agent + 
		     " found not role (" + notRole  + 
		     ") in community type (" + 
		     communityType + ")");
    WarnSchedulable ws =
      new WarnSchedulable(_threadService.getThread(this, tt), tt);
    CommunityChangeListener   ccl = 
      new GetCommunity(listener, ws, communityType, notRole, false);
    CommunityResponseListener crl = 
      new ResultListener(listener, ws, ccl, notRole, false, Community.COMMUNITIES_ONLY);
    String filter = "(CommunityType=" + communityType + ")";
    ws.schedule(COMMUNITY_WARNING_TIMEOUT, COMMUNITY_WARNING_TIMEOUT);
    if (_log.isDebugEnabled()) {
      _log.debug("In agent :"+ _agent +
		 " Doing Communities only search in getCommunityNoRole with filter :"
		 + filter);
      _log.debug(" Result listener in  getCommunityNoRole is :"+ crl);
    }
    Collection communities = 
      _cs.searchCommunity(null, filter, true, Community.COMMUNITIES_ONLY, crl);
   
    if (communities != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+"Got immediate response for community of type: "
		   + communityType + " in getCommunityNoRole"  );
      }
      Set commSet = withRole(communities, notRole, false);
      if (!commSet.isEmpty()) {
        ws.cancel();
        listener.getResponse(commSet);
        return;
      }
      if(_log.isDebugEnabled()){
        _log.debug("Adding Listener getCommunityNoRole with not role : "
		   + notRole + "Listener is :"+ ccl); 
      }
      _cs.addListener(ccl);
    } 
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+
		 "Waiting for callback ... In getCommunityNoRole ()"+ 
                 "Looking for community of type " + communityType +
                 " for which " + _agent + " does not have role " + notRole);
    }
  }
  /**
   * Retrieves the communities that the current agent belongs to.
   * If the current agent does not belong to any community of the
   * given type, the callback is called every time agent is added to 
   * a community .
   * <p>
   * When WARN logging is enabled, a message is displayed every
   * few minutes while the response has not been returned.
   *
   * @param communityType The type of community to return
   * @param listener A callback object that receives the results
   *                 of the lookup.
   */
  public void getCommunityWithUpdates(String communityType, 
                                      CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug("getCommunity called for agent : "+_agent);
    }
    getCommunityWithUpdates (communityType, MEMBER_ROLE, listener);
  }


  /**
   * Retrieves the communities that the current agent belongs to where
   * the agent has the given role.
   * If the current agent does not belong to any community of the
   * given type with the given role, the callback is called with the
   * first matching community
   * <p>
   * When WARN logging is enabled, a message is displayed every
   * few minutes while the response has not been returned.
   *
   * @param communityType The type of community to return
   * @param role          The agent's role in the community
   * @param listener A callback object that receives the results
   *                 of the lookup.
   */
  public void getCommunityWithUpdates(String communityType, 
                                      String role, 
                                      CommunityServiceUtilListener listener) {
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+" In getCommunityWithUpdates () Looking for community of type " + communityType);
    }
    final Runnable tt =
      new WarnThread(_agent + 
		     " searching for role (" + role + ") in community " +
		     "type (" + communityType + ")",
		     _agent + 
		     " found role (" + role  + ") in community type (" + 
		     communityType + ")");
    WarnSchedulable ws =
      new WarnSchedulable(_threadService.getThread(this, tt), tt);
    CommunityChangeListener   ccl = 
      new GetCommunityWithUpdates(listener, ws, communityType, role, true);
    CommunityResponseListener crl = 
      new ResultListener(listener, ws, ccl, role, true, Community.COMMUNITIES_ONLY);
    String filter = "(CommunityType=" + communityType + ")";
    ws.schedule(COMMUNITY_WARNING_TIMEOUT, COMMUNITY_WARNING_TIMEOUT);
    if (_log.isDebugEnabled()) {
      _log.debug("In agent :"+ _agent +" Doing Communities only search in  getCommunityWithUpdates  with filter :"+ filter);
      _log.debug(" Result listener in  getCommunityWithUpdates :"+ crl);
    }
    if(_log.isDebugEnabled()){
      _log.debug("Adding Listener getCommunityWithUpdates with :"+ role + "Listener is :"+ ccl); 
    }
    _cs.addListener(ccl);
    Collection communities = 
      _cs.searchCommunity(null, filter, true, Community.COMMUNITIES_ONLY, crl);
    
    if (communities != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+"Got immediate response for community of type: " + 
                   communityType);
      }
      Set commSet = withRole(communities, role, true);
      if (!commSet.isEmpty()) {
        listener.getResponse(commSet);
        ws.cancel();
        return;
      }
      
    } 
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+"Waiting for callback searching for community of type " +
                 communityType);
    }
  }

  /**
   * Retrieves the communities that the current agent belongs to.
   * If the current agent does not belong to any community of the
   * given type, the callback is called with the first community
   * of the given type that it belongs to.
   * <p>
   * When WARN logging is enabled, a message is displayed every
   * few minutes while the response has not been returned.
   *
   * @param communityType The type of community to return
   * @param listener A callback object that receives the results
   *                 of the lookup.
   */
  public void getCommunity(String communityType, 
                           CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug("getCommunity called for agent : "+_agent);
    }
    getCommunity(communityType, MEMBER_ROLE, listener);
  }

  /**
   * Retrieves the communities that the current agent belongs to where
   * the agent has the given role.
   * If the current agent does not belong to any community of the
   * given type with the given role, the callback is called with the
   * first matching community
   * <p>
   * When WARN logging is enabled, a message is displayed every
   * few minutes while the response has not been returned.
   *
   * @param communityType The type of community to return
   * @param role          The agent's role in the community
   * @param listener A callback object that receives the results
   *                 of the lookup.
   */
  public void getCommunity(String communityType, 
                           String role, 
                           CommunityServiceUtilListener listener) {
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+" In getCommunity () Looking for community of type " + communityType);
    }
    final Runnable tt =
      new WarnThread(_agent + 
		     " searching for role (" + role + ") in community " +
		     "type (" + communityType + ")",
		     _agent + 
		     " found role (" + role  + ") in community type (" + 
		     communityType + ")");
    WarnSchedulable ws =
      new WarnSchedulable(_threadService.getThread(this, tt), tt);
    CommunityChangeListener   ccl = 
      new GetCommunity(listener, ws, communityType, role, true);
    CommunityResponseListener crl = 
      new ResultListener(listener, ws, ccl, role, true, Community.COMMUNITIES_ONLY);
    String filter = "(CommunityType=" + communityType + ")";
    ws.schedule(COMMUNITY_WARNING_TIMEOUT, COMMUNITY_WARNING_TIMEOUT);
    if (_log.isDebugEnabled()) {
      _log.debug("In agent :"+ _agent +" Doing Communities only search in  getCommunity with filter :"+ filter);
      _log.debug(" Result listener in  getCommunity :"+ crl);
    }
    Collection communities = 
      _cs.searchCommunity(null, filter, true, Community.COMMUNITIES_ONLY, crl);

    if (communities != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+"Got immediate response for community of type: " + 
                   communityType);
      }
      Set commSet = withRole(communities, role, true);
      if (!commSet.isEmpty()) {
        ws.cancel();
        listener.getResponse(commSet);
        return;
      }
      checkCsBug(communities, Community.COMMUNITIES_ONLY);
      if(_log.isDebugEnabled()){
        _log.debug("Adding Listener getCommunity with :"+ role + "Listener is :"+ ccl); 
      }
      _cs.addListener(ccl);
    } 
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+"Waiting for callback searching for community of type " +
                 communityType);
    }
  }

  /**
   * Searches the communities of the type given that the current agent
   * belongs to and returns at least one agent which belongs to 
   * same community and has the given role. The result Set given
   * to the listener will have Agent Entities.
   * <p>
   * When WARN logging is enabled, a message is displayed every
   * few minutes while the response has not been returned.
   *
   * @param communityType The type of community to search
   * @param role          The role of the agent(s) to return
   * @param listener A callback object that receives the results
   *                 of the lookup.
   */
  public void getCommunityAgent(String communityType, 
                                String role,
                                CommunityServiceUtilListener listener) {
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+" In getCommunityAgent Looking for agent in community of type " + communityType +
                 " with a role of " + role);
    }

    final Runnable tt =
      new WarnThread(_agent + " searching for agent of role (" + role +
		     ") belonging to my community of " +
		     "type (" + communityType + ")", 
		     _agent + " found agent of role (" + role +
		     ") belonging to community type (" + communityType +
		     ")");
    WarnSchedulable ws =
      new WarnSchedulable(_threadService.getThread(this, tt), tt);
    CommunityChangeListener   ccl = 
      new GetAgent(listener, ws, communityType, role);
    CommunityResponseListener crl = new ResultListener(listener, ws, ccl, Community.AGENTS_ONLY);
    String filter = "(&(CommunityType=" + communityType + 
      ")(Role=" + role +"))";
    ws.schedule(COMMUNITY_WARNING_TIMEOUT, COMMUNITY_WARNING_TIMEOUT);
    if(_log.isDebugEnabled()){
      _log.debug("In agent :"+ _agent +" Doing Agents only search in  getCommunityAgent with filter :"+ filter);
      _log.debug(" Result listener in  getCommunityAgent is :"+ crl);
    }
    Collection agents = 
      _cs.searchCommunity(null, filter, true, Community.AGENTS_ONLY, crl);

    if (agents != null) {
      ws.cancel();
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+" getCommunityAgent() Got immediate response when looking for agents in role (" +
                   role + ") in my communities of type (" +
                   communityType + ")" +"   Response   :"+ agents );
      }
      if (agents.isEmpty()) {
        if(_log.isDebugEnabled()){
          _log.debug("Adding Listener getCommunityAgent with :"+ role + "Listener is :"+ ccl); 
        }
        _cs.addListener(ccl);
      } else {
        checkCsBug(agents, Community.AGENTS_ONLY);
        HashSet set = new HashSet(agents);
        listener.getResponse(set);
        ws.cancel();
      }
    } else {
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+ "Waiting for callback searching for agent in " +
                   "community of type (" + communityType + ") having role (" + 
                   role + ")");
      }
    }
  }

  /**
   * Checks the consistency of the community service.
   * Logs an error if a set of entities contains at least one entity
   * of the wrong type.
   * @param agents
   */
  private void checkCsBug(Collection entities, int searchType) {
    Iterator it = entities.iterator();
    while (it.hasNext()) {
      Entity e = (Entity)it.next();
      if (_log.isErrorEnabled()) { 
      	if (searchType == Community.COMMUNITIES_ONLY && e instanceof Agent) {
          _log.error("Bug in the community service. Entity " + e.getName()
                + " (which is an agent) has been returned by cs.search(... Community.COMMUNITIES_ONLY...)",
                new Throwable());
          it.remove();
        }
        else if (searchType == Community.AGENTS_ONLY && e instanceof Community) {
          _log.error("Bug in the community service. Entity " + e.getName()
              + " (which is a community) has been returned by cs.search(... Community.AGENTS_ONLY...)",
                            new Throwable());
          it.remove();
        }
      }
    }
  }
  
  /**
   * Searches the community of the given name that
   * and returns agents with the given role that belong to that community.
   * If the information isn't available after the CommunityService responds,
   * <tt>null</tt> is returned. This call only blocks as long as
   * <tt>timeout</tt> milliseconds. If the timeout passes, <tt>null</tt>
   * is returned.
   *
   * @param communityName The name of community to search
   * @param role          The role of the agent(s) to return
   * @param timeout       The maximum wait time (in milliseconds)
   */
  public Set getAgents(String communityName, 
                       String role, long timeout) {
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+"In getAgents Looking for agent in community (" + communityName +
                 ") with a role of (" + role + ")"); 
    }

    final Status status = new Status();
    final Semaphore s = new Semaphore(0);

    CommunityResponseListener crl = new CommunityResponseListener() {
        public void getResponse(CommunityResponse resp) {
          Object response = resp.getContent();
          if (_log.isDebugEnabled()) {
            _log.debug("Agent "+ _agent+"got response in callback: " + response);
          }
          if (!(response instanceof Set)) {
            String errorString = "Agent "+ _agent+"Unexpected community response class:"
              + response.getClass().getName() + " - Should be a Community";
            _log.error(errorString);
            throw new RuntimeException(errorString);
          }
          status.value = response;
          s.release();
        }
      };
    String filter = "(Role=" + role +")";
    if(_log.isDebugEnabled()){
      _log.debug("In agent :"+ _agent +" Doing Agents only search in  getAgents with filter :"+ filter);
      _log.debug(" Result listener in  getAgents is :"+ crl);
    }
    Collection agents = 
      _cs.searchCommunity(communityName, filter, true, 
                          Community.AGENTS_ONLY, crl);
    if (agents != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+" getAgents() Got immediate response when looking for agents in role (" +
                   role + ") in community (" + communityName + ")" +  "   Response :  "+ agents);
      }
      HashSet set = new HashSet(agents);
      return set;
    } 

    try {
      if (s.attempt(timeout)) {
        return (Set) status.value;
      }
      return null;
    } catch (InterruptedException e) {
      return null;
    }
  }

  /**
   * Searches the community of the given name that
   * and returns agents with the given role that belong to that community.
   * If the information isn't available after the CommunityService responds,
   * <tt>null</tt> is returned. 
   *
   * @param communityName The name of community to search
   * @param role          The role of the agent(s) to return
   * @param callback      Listener that receives the results of the search
   */
  public void getAgents(String communityName, String role, 
                        final CommunityServiceUtilListener listener) {
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+" In  getAgents(String communityName, String role,"+ 
                 "final CommunityServiceUtilListener listener )Looking for agent in community (" + communityName +
                 ") with a role of (" + role + ")");
    }

    final Runnable tt =
      new WarnThread(_agent + " searching for agent of role (" + role +
		     ") in community (" + communityName + ")",
		     _agent + " found agent of role (" + role +
		     ") in community (" + communityName + ")");

    final WarnSchedulable ws =
      new WarnSchedulable(_threadService.getThread(this, tt), tt);
    CommunityResponseListener crl = new CommunityResponseListener() {
        public void getResponse(CommunityResponse resp) {
          Object response = resp.getContent();
          if (_log.isDebugEnabled()) {
            _log.debug("Agent "+ _agent+"got response in callback get Agents (communityName,role,listener) : " + response);
          }
          if (!(response instanceof Set)) {
            String errorString = "Unexpected community response class:"
              + response.getClass().getName() + " - Should be a Community";
            _log.error(errorString);
            throw new RuntimeException(errorString);
          }
          ws.cancel();
          if(_log.isDebugEnabled()) {
            _log.debug("received response in call back of crl for get Agents (communityName,role,listener) :"
                       + response);
          }
          listener.getResponse((Set) response);
        }
      };

    String filter = "(Role=" + role +")";
    ws.schedule(COMMUNITY_WARNING_TIMEOUT, COMMUNITY_WARNING_TIMEOUT);
    if(_log.isDebugEnabled()){
      _log.debug("In agent :"+ _agent +" Doing Agents only search in  getAgents with filter :"+ filter);
      _log.debug(" Community listener  in  getAgents is :"+ crl);
    } 
    Collection agents = 
      _cs.searchCommunity(communityName, filter, true, 
                          Community.AGENTS_ONLY, crl);

    if (agents != null) {
      if(_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+" getAgents Got immediate Response in getAgents when looking for agents in role  (" +
                   role + ") in community (" + communityName + ")" + "Response :"+ agents);
      }
      ws.cancel();
      HashSet set = new HashSet(agents);
      listener.getResponse(set);
    }
  }


  /**
   * Searches the community of the given name that
   * and returns agents with the given role that belong to that community.
   * If the information isn't available CommunityChange listener is added,
   * <tt>null is never returned </tt> is returned. 
   *
   * @param communityName The name of community to search
   * @param role          The role of the agent(s) to return
   * @param callback      Listener that receives the results of the search
   */
  public void getAgentsInCommunity(String communityName, String role, 
                                   final CommunityServiceUtilListener listener, String communityType) {
    if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+"In getAgentsInCommunity(String communityName, String role,"+ 
                 "final CommunityServiceUtilListener listener)Looking for agent in community (" + communityName +
                 ") with a role of (" + role + ")");
    }

    final Runnable tt =
      new WarnThread(_agent + " searching for agent of role (" + role +
		     ") in community (" + communityName + ") in getAgentsInCommunity ",
		     _agent + " found agent of role (" + role +
		     ") in community (" + communityName + ")");
    WarnSchedulable ws =
      new WarnSchedulable(_threadService.getThread(this, tt), tt);
    /*
      CommunityResponseListener ccrl = new CommunityResponseListener() {
      public void getResponse(CommunityResponse resp) {
      Object response = resp.getContent();
      if (_log.isDebugEnabled()) {
      _log.debug("Agent "+ _agent+"got response in callback getAgentsInCommunity(communityName,role,listener) : " + response);
      }
      if (!(response instanceof Set)) {
      String errorString = "Unexpected community response class:"
      + response.getClass().getName() + " - Should be a Community";
      _log.error(errorString);
      throw new RuntimeException(errorString);
      }
      ws.cancel();
      if(_log.isDebugEnabled()) {
      _log.debug("received response in call back of crl for getAgentsInCommunity(communityName,role,listener) :"
      + response);
      }
      listener.getResponse((Set) response);
      }
      };
    */
    CommunityChangeListener   ccl =  new GetAgentInCommunity (listener, ws, communityName, role,communityType);
    CommunityResponseListener crl =  new ResultListener(listener, ws, ccl, Community.AGENTS_ONLY);
    String filter = "(Role=" + role +")";
    ws.schedule(COMMUNITY_WARNING_TIMEOUT, COMMUNITY_WARNING_TIMEOUT);
    if(_log.isDebugEnabled()){
      _log.debug("In agent :"+ _agent +" Doing Agents only search in  getAgentsInCommunity with filter :"+ filter);
      _log.debug(" Result listener in  getAgentsInCommunity is :"+ crl);
    }  
    Collection agents = 
      _cs.searchCommunity(communityName, filter, true, 
                          Community.AGENTS_ONLY, crl);

    if (agents != null) {
      if(_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+" getAgentsInCommunity Got immediate Response in getAgents when looking for agents in role  (" +
                   role + ") in community (" + communityName + ")" + "Response :"+ agents);
      }
      if(agents.isEmpty()) {
        if(_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+" Got immediate Response  in getAgents as EMPTY ADDING CRL WAITING for CALL BACK.. "); 
          _log.debug(" ADDING Listener getAgentsInCommunity role :" + role + "Listener :" + ccl);
        }
        
        _cs.addListener(ccl);
      } else {
        ws.cancel();
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+" getAgentsInCommunity Got immediate response when looking for agents in role (" +
                     role + ") in community (" + communityName + ")" + "Response :"+ agents);
        }
        HashSet set = new HashSet(agents);
        listener.getResponse(set);
      }
    }
  }
  

  /**
   * Retrieves the security community for which this agent has the role
   * <tt>"Manager"</tt>.
   *
   * @param listener Callback receives at least one security community
   *                 in its getResponse.
   */
  public void  getManagedSecurityCommunity(CommunityServiceUtilListener listener) {
    if(_log.isDebugEnabled()) {
      _log.debug(" getManagedSecurityCommunity called for :"+_agent);
    }
    getCommunity(MONITORING_SECURITY_COMMUNITY_TYPE, MANAGER_ROLE, listener);
  }

  /**
   * Retrives the security communities for which this agent is manager.
   * When an agent is discovered to be root or not, the listener is
   * called with managed Community if the agent is root. Otherwise
   * an empty set is returned in the getResponse()
   */
  public void amIRoot(final CommunityServiceUtilListener listener) {
    CommunityServiceUtilListener rootListener = 
      new CommunityServiceUtilListener() {
        public void getResponse(Set set) {
          Iterator iter = set.iterator();
          while (iter.hasNext()) {
            Community community = (Community) iter.next();
            if (hasRole(community, MANAGER_ROOT, true)) {
              listener.getResponse(set);
              return;
            }
          }
          listener.getResponse(new HashSet());
        }
      };
    getManagedSecurityCommunity(rootListener);
  }

  public boolean containsEntity(Set set, String agent) {
    boolean contains=false;
    if(set==null) { 
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+ " returning as set is NULL");
      }
      return contains;
    }
    if(set.isEmpty()) {
      if (_log.isDebugEnabled()) {
        _log.debug("Agent "+ _agent+ " returning as set is EMPTY");
      }
      return contains;
    }
    Iterator iter=set.iterator();
    Entity entity=null;
    while(iter.hasNext()){
      entity=(Entity)iter.next();
      if (_log.isDebugEnabled()) {
        _log.debug( "Agent "+ _agent+ "comparing : "+ entity.getName() + " with "+ agent);
      }
      if(entity.getName().trim().equals(agent)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+ " Found : "+ entity.getName().trim() + " EQUALS" + agent);
        }
        contains=true;
        return contains; 
      }
    }
    return contains;
  }
  private class Status {
    public Object value;
  }

  private void printCommunityInfo(Community community) {
    if(_log.isDebugEnabled()) {
      _log.debug("Printing Community info for community :"+ community.getName());
      Collection entities=community.getEntities();
      Iterator iter=entities.iterator();
      Entity entity=null;
      while(iter.hasNext()){
        entity=(Entity)iter.next();
        _log.debug("Entity -->"+entity.getName());
        _log.debug(entity.toXml());
      }
    }
  }
  private static boolean isCommunityType(Community community, String type) {
    try {
      Attributes attrs = community.getAttributes();
      Attribute attr = attrs.get("CommunityType");
      if (attr == null) {
        return false;
      }
      for (int i = 0; i < attr.size(); i++) {
        Object t = attr.get(i);
        if (type.equals(t)) {
          return true;
        }
      }
      return false;
    } catch (NamingException e) {
      throw new RuntimeException("This should never happen");
    }
  }

  private class GetCommunity implements CommunityChangeListener {
    private String                       _communityType;
    private String                       _role;
    private CommunityServiceUtilListener _listener;
    private WarnSchedulable              _timerTask;
    private boolean                      _allDone;
    private boolean                      _containsRole;

    public GetCommunity(CommunityServiceUtilListener listener, 
                        WarnSchedulable timerTask,
                        String communityType,
                        String role,
                        boolean containsRole) {
      _communityType = communityType;
      _role          = role;
      _listener      = listener;
      _timerTask     = timerTask;
      _containsRole  = containsRole;
    }

    synchronized public void communityChanged(CommunityChangeEvent event) {
      if (_log.isDebugEnabled()) {
        _log.debug(" communityChanged is called for agent : "
		   +_agent +" in GetCommunity CommunityChangeListener" + this);
        if(_containsRole){
          _log.debug(" where community Type( "+_communityType+" ) and role is ( "+_role+ " )"); 
        }
        else {
          _log.debug(" where community Type( "+_communityType+" ) and role is NOT ( "+_role+ " )"); 
        }
      }
      
      if (_allDone) {
        if (_log.isDebugEnabled()) {
          _log.debug("Removing communityChanged listener for agent : "+ _agent +" in GetCommunity CommunityChangeListener" + this );
        }
        _cs.removeListener(this);
        return;
      }
      if (event.getType() != CommunityChangeEvent.ADD_COMMUNITY &&
          event.getType() != CommunityChangeEvent.ENTITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.COMMUNITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.ADD_ENTITY) {
        return; // not a change we care about
      }
      Community community = event.getCommunity();
      if (!isCommunityType(community, _communityType)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+ " "+community.getName() + " is not of type " + 
                     _communityType);
        }
        return;
      }

      if (_log.isDebugEnabled()) {
        _log.debug(" Change Info for Agent "+ _agent+ " community change: " + 
                   CommunityChangeEvent.getChangeTypeAsString(event.getType()) +
                   ", " +
                   event.getWhatChanged());
      }
      printCommunityInfo(community);
      if (hasRole(community, _role, _containsRole)) {
        // found it!
        _allDone = true;
        _timerTask.cancel();
        _cs.removeListener(this);
        if (_log.isDebugEnabled()) {
          _log.debug(" Setting response for agent : "+_agent +" in GetCommunity CommunityChangeListener ");
          if(_containsRole){
            _log.debug(" where community Type( "+_communityType+" ) and role is ( "+_role+ " )"); 
          }
          else {
            _log.debug(" where community Type( "+_communityType+" ) and role is NOT ( "+_role+ " )"); 
          }
          _log.debug(" Response is : "+ community);
        }
        _listener.getResponse(Collections.singleton(community));
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug(_agent + " does not have role (" + _role + 
                   ") in community (" + community.getName() + ")");
        _log.debug(" Waiting for response for agent : "+_agent +" in GetCommunity CommunityChangeListener ");
      }
    }

    public String getCommunityName() {
      return null; // all MY communities
    }
  };

  private class GetCommunityWithUpdates implements CommunityChangeListener {
    private String                       _communityType;
    private String                       _role;
    private CommunityServiceUtilListener _listener;
    private WarnSchedulable              _timerTask;
    private boolean                      _allDone;
    private boolean                      _containsRole;

    public GetCommunityWithUpdates(CommunityServiceUtilListener listener, 
                                   WarnSchedulable timerTask,
                                   String communityType,
                                   String role,
                                   boolean containsRole) {
      _communityType = communityType;
      _role          = role;
      _listener      = listener;
      _timerTask     = timerTask;
      _containsRole  = containsRole;
    }

    public void communityChanged(CommunityChangeEvent event) {
      if (_log.isDebugEnabled()) {
        _log.debug(" communityChanged is called for agent : "
		   +_agent +" in GetCommunityWithUpdates CommunityChangeListener"
		   + this);
        if(_containsRole){
          _log.debug(" where community Type( "+_communityType+" ) and role is ( "+_role+ " )"); 
        }
        else {
          _log.debug(" where community Type( "+_communityType+" ) and role is NOT ( "+_role+ " )"); 
        }
      }
      
      if (event.getType() != CommunityChangeEvent.ADD_COMMUNITY &&
          event.getType() != CommunityChangeEvent.ENTITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.COMMUNITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.ADD_ENTITY) {
        return; // not a change we care about
      }
      Community community = event.getCommunity();
      if (!isCommunityType(community, _communityType)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+ " "+community.getName() + " is not of type " + 
                     _communityType);
        }
        return;
      }

      if (_log.isDebugEnabled()) {
        _log.debug(" Change Info for Agent "+ _agent+ " GetCommunityWithUpdates community change: " + 
                   CommunityChangeEvent.getChangeTypeAsString(event.getType()) +
                   ", " +
                   event.getWhatChanged());
      }
      printCommunityInfo(community);
      if (hasRole(community, _role, _containsRole)) {
        // found it!
        if (_log.isDebugEnabled()) {
          _log.debug(" Setting response for agent : "+_agent +" in GetCommunityWithUpdates CommunityChangeListener ");
          if(_containsRole){
            _log.debug(" where community Type( "+_communityType+" ) and role is ( "+_role+ " )"); 
          }
          else {
            _log.debug(" where community Type( "+_communityType+" ) and role is NOT ( "+_role+ " )"); 
          }
          _log.debug(" Response in  is : "+ community);
        }
        _listener.getResponse(Collections.singleton(community));
        _timerTask.cancel();
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug(_agent + " does not have role (" + _role + 
                   ") in community (" + community.getName() + ")");
        _log.debug(" Waiting for response for agent : "+_agent +" in GetCommunityWithUpdates CommunityChangeListener ");
      }
    }

    public String getCommunityName() {
      return null; // all MY communities
    }
  }; 

  private class GetAgent implements CommunityChangeListener {
    private String                       _communityType;
    private CommunityServiceUtilListener _listener;
    private WarnSchedulable              _timerTask;
    private String                       _role;
    private boolean                      _allDone;

    public GetAgent(CommunityServiceUtilListener listener, 
                    WarnSchedulable timerTask,
                    String communityType,
                    String role) {
      _communityType = communityType;
      _listener = listener;
      _timerTask = timerTask;
      _role = role;
    }

    public void communityChanged(CommunityChangeEvent event) {
      if (_log.isDebugEnabled()) {
        _log.debug("communityChanged called for agent : "+ _agent +" in GetAgent CommunityChangeListener" + this );
      }
      if (_allDone) {
        if (_log.isDebugEnabled()) {
          _log.debug("Removing communityChanged listener for agent : "+ _agent +" in GetAgent CommunityChangeListener");
        }
        _cs.removeListener(this);
        return;
      }
      
      if (event.getType() != CommunityChangeEvent.ADD_COMMUNITY &&
          event.getType() != CommunityChangeEvent.ENTITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.COMMUNITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.ADD_ENTITY) {
        return; // not a change we care about
      }
      Community community = event.getCommunity();
      if (!isCommunityType(community, _communityType)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+" " +community.getName() + " is not of type " + 
                     _communityType);
        }
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug(" Change Info for Agent "+ _agent+" community change: " + 
                   CommunityChangeEvent.getChangeTypeAsString(event.getType()) +
                   ", " +
                   event.getWhatChanged());
        // printCommunityInfo(community);
      }
      printCommunityInfo(community);
      // Now while I understand that if the CommunityService is telling
      // me about this community, I must be a member, I don't trust it.
      // I'll check the membership.
      if (!hasRole(community, MEMBER_ROLE, true)) {
        if (_log.isDebugEnabled()) {
          _log.debug(_agent + " is not really part of (" + 
                     community.getName() + ") yet");
          _log.debug("Waiting for Response for agent : "+ _agent +" in GetAgent CommunityChangeListener");
        }
        return;
      }
      Set set = community.search("(Role=" + _role + ")", 
                                 Community.AGENTS_ONLY);
      if (set.isEmpty()) {
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+ " There are no members of role (" + _role +
                     ") in community (" + 
                     community.getName() + ") yet");
          _log.debug("Waiting for Response for agent : "+ _agent +" in GetAgent CommunityChangeListener");
        }
        return;
      }
      _timerTask.cancel();
      _allDone = true;
      _cs.removeListener(this);
      if (_log.isDebugEnabled()) {
        _log.debug("Receive response  for agent : "+ _agent +"in GetAgent CommunityChangeListener");
        _log.debug("Response is : "+set); 
         
      }
      _listener.getResponse(set);
    }

    public String getCommunityName() {
      return null; // all MY communities
    }

  };

  private static final long MILLISECOND = 1;
  private static final long SECOND      = 1000 * MILLISECOND;
  private static final long MINUTE      = 60 * SECOND;
  private static final long HOUR        = 60 * MINUTE;
  private static final long DAY         = 24 * HOUR;
  private static final long TIMES[] = {
    DAY, HOUR, MINUTE, SECOND
  };

  private static final String TIMES_STR[] = {
    "day", "hour", "minute", "second"
  };

  private class WarnSchedulable implements Schedulable {
    private Schedulable _sched;
    private WarnThread _wt;

    public WarnSchedulable(Schedulable s, Runnable wt) {
      _sched = s;
      _wt = (WarnThread) wt;
    }
    public boolean cancel() {
      if (_sched.cancel()) {
        if (_log.isInfoEnabled()) {
          _log.info(_wt.getFound() + ": " + _wt.elapsedTime());
        }
        return true;
      } 
      return false;
    }
    public int getLane() {
      return _sched.getLane();
    }
    public void cancelTimer() {
      _sched.cancelTimer();
    }
    public Object getConsumer() {
      return _sched.getConsumer();
    }
    public int getState() {
      return _sched.getState();
    }
    public void schedule(long delay) {
      _sched.schedule(delay);
    }
    public void schedule(long delay, long interval) {
      _sched.schedule(delay, interval);
    }
    public void scheduleAtFixedRate(long delay, long interval) {
      _sched.scheduleAtFixedRate(delay, interval);
    }
    public void start() {
      _sched.start();
    }
    public String getWarning() {
      return _wt.getWarning();
    }
  }

  private class WarnThread implements Runnable {
    private String _warning;
    private String _found;
    private long   _startTime = System.currentTimeMillis();

    public WarnThread(String warning, String found) {
      _warning = warning;
      _found    = found;
    }

    public void run() {
      if (_log.isWarnEnabled()) {
        _log.warn(_warning + ": " + elapsedTime());
      }
    }

    public String getFound() {
      return _found;
    }

    public String elapsedTime() {
      long now = System.currentTimeMillis();
      long diff = now - _startTime;
      StringBuffer sb = new StringBuffer();

      for (int i = 0; i < TIMES.length; i++) {
        int time = (int) (diff/TIMES[i]);
        if (time > 0) {
          if (sb.length() > 0) {
            sb.append(' ');
          }
          sb.append(String.valueOf(time));
          sb.append(' ');
          sb.append(TIMES_STR[i]);
          if (time > 1) {
            sb.append('s');
          }
          diff -= time * TIMES[i];
        }
      }
      return sb.toString();
    }

    public String getWarning(){
      return _warning;
    }
  }

	private class ResultListener implements CommunityResponseListener {
		private WarnSchedulable _ws;
		private CommunityServiceUtilListener _listener;
		private CommunityChangeListener _changeListener;
		private String _role;
		boolean _containsRole;
		boolean _answered = false;
    int _searchType = -1;
    
		public ResultListener(CommunityServiceUtilListener listener,
				WarnSchedulable warningTask,
				CommunityChangeListener changeListener,
        int searchType) {
			this(listener, warningTask, changeListener, null, false, searchType);
		}
        
		/**
		 * @param listener
		 * @param warningTask
		 * @param changeListener
		 * @param role
		 * @param containsRole
		 * @param searchType - Used for debug purposes only.
		 */
		public ResultListener(CommunityServiceUtilListener listener,
				WarnSchedulable warningTask,
				CommunityChangeListener changeListener, String role,
				boolean containsRole, int searchType) {
			if (warningTask == null) {
				if (_log.isErrorEnabled()) {
					_log.error("Warning task has not been set");
				}
				throw new IllegalArgumentException(
						"Warning task has not been set");
			}
			if (listener == null) {
				if (_log.isErrorEnabled()) {
					_log.error("Listener has not been set");
				}
				throw new IllegalArgumentException("Listener has not been set");
			}
			if (changeListener == null) {
				if (_log.isErrorEnabled()) {
					_log.error("changeListener has not been set");
				}
				throw new IllegalArgumentException(
						"changeListener has not been set");
			}
			_ws = warningTask;
			_listener = listener;
			_changeListener = changeListener;
			_role = role;
			_containsRole = containsRole;
      _searchType = searchType;
		}
        
		public synchronized void getResponse(CommunityResponse resp) {
			if (!_answered) {
				_answered = true;
			} else {
				return;
			}
			if (_log.isDebugEnabled()) {
				_log.debug("Result listener called :" + this + " - Status: "
						+ resp.getStatusAsString());
			}
			if (resp.getStatus() == CommunityResponse.SUCCESS) {
				Object response = resp.getContent();
				if (response == null) {
					if (_log.isInfoEnabled()) {
						_log.info("ResultListener (agent:" + _agent
								+ "): response is null");
					}
					// didn't find any appropriate community. Start a listener
					addListener();
					return;
				}
				if (!(response instanceof Set)) {
					String errorString = "Agent " + _agent
							+ " Unexpected community response class:"
							+ response.getClass().getName()
							+ " - Should be a Set";
					_log.error(errorString);
					throw new RuntimeException(errorString);
				}
				Set set = (Set) response;
				if (_role != null) {
					set = withRole(set, _role, _containsRole);
				}
				if (!set.isEmpty()) {
					if (_log.isDebugEnabled()) {
						_log
								.debug("Received Response in Result Listener------- :");
						_log.debug(_ws.getWarning());
						if (_containsRole) {
							_log.debug(" For role :" + _role);
						} else {
							_log.debug(" When role is not :" + _role);
						}
					}
          checkCsBug(set, _searchType);
					_listener.getResponse(set);
					_ws.cancel();
					return;
				}
			}
			// didn't find any appropriate community. Start a listener
			addListener();
		}
		/**
		 * Invoked when we didn't find any appropriate community. Start a listener
		 */
		private void addListener() {
			if (_log.isDebugEnabled()) {
				_log.debug(_ws.getWarning());
				if (_containsRole) {
					_log.debug(" For role :" + _role);
				} else {
					_log.debug(" When role is not :" + _role);
				}
				_log.debug("Adding Listener in Result Listener :"
						+ _changeListener);
			}
			// didn't find any appropriate community... start a listener
			_cs.addListener(_changeListener);
		}
	}
   
  private class GetAgentInCommunity implements CommunityChangeListener {
    private String                       _communityName;
    private String                      _communityType;
    private CommunityServiceUtilListener _listener;
    private WarnSchedulable              _timerTask;
    private String                       _role;
    private boolean                      _allDone;

    public GetAgentInCommunity(CommunityServiceUtilListener listener, 
                               WarnSchedulable timerTask,
                               String communityName,
                               String role, String communityType) {
      _communityName = communityName;
      _listener = listener;
      _timerTask = timerTask;
      _role = role;
    }

    public synchronized void communityChanged(CommunityChangeEvent event) {
      if (_log.isDebugEnabled()) {
        _log.debug("communityChanged called for agent : "+ _agent +" in GetAgentInCommunity CommunityChangeListener" + this);
      }
      if (_allDone) {
        if (_log.isDebugEnabled()) {
          _log.debug("Removing communityChanged listener for agent : "+ _agent +" in GetAgentInCommunity CommunityChangeListener");
        }
        _cs.removeListener(this);
        return;
      }
      if (event.getType() != CommunityChangeEvent.ADD_COMMUNITY &&
          event.getType() != CommunityChangeEvent.ENTITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.COMMUNITY_ATTRIBUTES_CHANGED &&
          event.getType() != CommunityChangeEvent.ADD_ENTITY) {
        return; // not a change we care about
      }
      Community community = event.getCommunity();
      
      if(_communityName!=null){
        if(!(community.getName().equals(_communityName))){
          if (_log.isDebugEnabled()) {
            _log.debug("Agent "+ _agent+" " +community.getName() + " is not the community  .We are looking for " +_communityName);
            _log.debug("Waiting for response in agent : "+_agent + " in GetAgentInCommunity CommunityChangeListener when community name are not same ");
          }
          return;
        }
      }
      else {
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+ "community :  " +community.getName() + " Passed Communityname is null:");
        }
      }
      if(_communityType!=null){
        if (!isCommunityType(community,_communityType)) {
          if (_log.isDebugEnabled()) {
            _log.debug("Agent "+ _agent+" " +community.getName() + " is not of type " + 
                       _communityType);
            _log.debug("Waiting for response in agent : "+_agent + " in GetAgentInCommunity CommunityChangeListener");
          }
          return;
        }
      }
      

      if (_log.isDebugEnabled()) {
        _log.debug(" Change Info for Agent "+ _agent+" community change: " + 
                   CommunityChangeEvent.getChangeTypeAsString(event.getType()) +
                   ", " +
                   event.getWhatChanged());
      }
      printCommunityInfo(community);
      
      // Now while I understand that if the CommunityService is telling
      // me about this community, I must be a member, I don't trust it.
      // I'll check the membership.
      /*
        if (!hasRole(community,_role, true)) {
        if (_log.isDebugEnabled()) {
        _log.debug(_agent + " is not really part of (" + 
        community.getName() + ") yet");
        _log.debug("Waiting for response in agent : "+_agent + " in GetAgentInCommunity CommunityChangeListener");
        }
        return;
        }
      */
      Set set = community.search("(Role=" + _role + ")", 
                                 Community.AGENTS_ONLY);
      if (set.isEmpty()) {
        if (_log.isDebugEnabled()) {
          _log.debug("Agent "+ _agent+ " There are no members of role (" + _role +
                     ") in community (" + 
                     community.getName() + ") yet");
          _log.debug("Waiting for response in agent : "+_agent + " in GetAgentInCommunity CommunityChangeListener");
        }
        return;
      }
      _timerTask.cancel();
      if(_log.isDebugEnabled()) {
        _log.debug("Received  response in agent : "+_agent + " in GetAgentInCommunity CommunityChangeListener");
        _log.debug("Response : "+set);
      }  
      _allDone = true;
      _cs.removeListener(this);
      _listener.getResponse(set);
    }
    public String getCommunityName() {
      return null; // all MY communities
    }
  }
  
  public static boolean isRequestValid(Request request, String msgSource) {
    boolean valid = true;
    int requestType = request.getRequestType();
    if(requestType == Request.JOIN  ||
       requestType == Request.LEAVE ||
       requestType == Request.MODIFY_ATTRIBUTES) {
      // hard coded for now, but in the future, we will have a policy that may allow
      // an agent to issue community service request on behalf of another agent.
      Entity e = request.getEntity();
      if(e != null && e instanceof Agent) {
        if(!(request.getSource().toString().equals(msgSource) &&
             e.getName().equals(msgSource))) {
          valid = false;
        }
      }
      // else handle CommunityImpl
    }
    return valid; 
  }
}
