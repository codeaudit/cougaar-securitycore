/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
package org.cougaar.core.security.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityChangeEvent;

import EDU.oswego.cs.dl.util.concurrent.Semaphore;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.TimerTask;
import javax.naming.directory.*;
import javax.naming.*;

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
  public static final String MANAGER_ROLE = "Manager";
  public static final String MANAGER_ROOT = "Root";
  public static final String MEMBER_ROLE = "Member";
  private static final String ROLE_FILTER = "(Role=" + MANAGER_ROLE +")";
  private static final String ROLE_MEMBER_FILTER = "(Role=" + MEMBER_ROLE +")";
  private static final String ROOT_FILTER = "(&(Role=" + MANAGER_ROLE +")" +
  "(Role=" + MANAGER_ROOT + "))";

  
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
  public void findSecurityManager(CommunityServiceUtilListener listener) {
    getCommunityAgent(SECURITY_COMMUNITY_TYPE, MANAGER_ROLE, listener);
  }

  public boolean isRoot(Community community) {
    Set set = community.search(ROOT_FILTER, Community.AGENTS_ONLY);
    return !set.isEmpty();
  }
  
  public boolean hasRole(Community community, String role) {
    Set set = community.search("(Role=" + role + ")",
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

  public Set withRole(Collection communities, String role) {
    Set commSet = new HashSet();
    Iterator iter = communities.iterator();
    while (iter.hasNext()) {
      Community community = (Community) iter.next();
      if (hasRole(community, role)) {
        commSet.add(community);
      }
    }
    return commSet;
  }

  /**
   * Retrieves all security communities for which this agent is a member
   */
  public void getSecurityCommunities(CommunityServiceUtilListener listener) {
    getCommunity(SECURITY_COMMUNITY_TYPE, MEMBER_ROLE, listener);
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
      _log.debug("Looking for community of type " + communityType);
    }

    final TimerTask tt =
      new WarnTimerTask(_agent + 
                        " searching for role (" + role + ") in community " +
                        "type (" + communityType + ")",
                        _agent + 
                        " found role (" + role  + ") in community type (" + 
                        communityType + ")");
    CommunityChangeListener   ccl = 
      new GetCommunity(listener, tt, communityType, role);
    CommunityResponseListener crl = 
      new ResultListener(listener, tt, ccl, role);
    String filter = "(CommunityType=" + communityType + ")";
    _threadService.schedule(tt, COMMUNITY_WARNING_TIMEOUT,
                            COMMUNITY_WARNING_TIMEOUT);
    Collection communities = 
      _cs.searchCommunity(null, filter, true, Community.COMMUNITIES_ONLY, crl);

    if (communities != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Got immediate response for community of type: " + 
                   communityType);
      }
      Set commSet = withRole(communities, role);
      if (!commSet.isEmpty()) {
        tt.cancel();
        listener.getResponse(commSet);
        return;
      }
      _cs.addListener(ccl);
    } 
    if (_log.isDebugEnabled()) {
      _log.debug("Waiting for callback searching for community of type " +
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
      _log.debug("Looking for agent in community of type " + communityType +
                 " with a role of " + role);
    }

    final TimerTask tt =
      new WarnTimerTask(_agent + " searching for agent of role (" + role +
                        ") belonging to my community of " +
                        "type (" + communityType + ")", 
                        _agent + " found agent of role (" + role +
                        ") belonging to community type (" + communityType +
                        ")");
    CommunityChangeListener   ccl = 
      new GetAgent(listener, tt, communityType, role);
    CommunityResponseListener crl = new ResultListener(listener, tt, ccl);
    String filter = "(&(CommunityType=" + communityType + 
      ")(Role=" + role +"))";
    _threadService.schedule(tt, COMMUNITY_WARNING_TIMEOUT,
                            COMMUNITY_WARNING_TIMEOUT);
    Collection agents = 
      _cs.searchCommunity(null, filter, true, Community.AGENTS_ONLY, crl);

    if (agents != null) {
      tt.cancel();
      if (_log.isDebugEnabled()) {
        _log.debug("Got immediate response when looking for agents in role (" +
                   role + ") in my communities of type (" +
                   communityType + ")");
      }
      HashSet set = new HashSet(agents);
      listener.getResponse(set);
    } else {
      if (_log.isDebugEnabled()) {
        _log.debug("Waiting for callback searching for agent in " +
                   "community of type (" + communityType + ") having role (" + 
                   role + ")");
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
      _log.debug("Looking for agent in community (" + communityName +
                 ") with a role of (" + role + ")");
    }

    final Status status = new Status();
    final Semaphore s = new Semaphore(0);

    CommunityResponseListener crl = new CommunityResponseListener() {
        public void getResponse(CommunityResponse resp) {
          Object response = resp.getContent();
          if (_log.isDebugEnabled()) {
            _log.debug("got response in callback: " + response);
          }
          if (!(response instanceof Set)) {
            String errorString = "Unexpected community response class:"
              + response.getClass().getName() + " - Should be a Community";
            _log.error(errorString);
            throw new RuntimeException(errorString);
          }
          status.value = response;
          s.release();
        }
      };

    String filter = "(Role=" + role +")";
    Collection agents = 
      _cs.searchCommunity(communityName, filter, true, 
                          Community.AGENTS_ONLY, crl);

    if (agents != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Got immediate response when looking for agents in role (" +
                   role + ") in community (" + communityName + ")");
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
      _log.debug("Looking for agent in community (" + communityName +
                 ") with a role of (" + role + ")");
    }

    final TimerTask tt =
      new WarnTimerTask(_agent + " searching for agent of role (" + role +
                        ") in community (" + communityName + ")",
                        _agent + " found agent of role (" + role +
                        ") in community (" + communityName + ")");

    CommunityResponseListener crl = new CommunityResponseListener() {
        public void getResponse(CommunityResponse resp) {
          Object response = resp.getContent();
          if (_log.isDebugEnabled()) {
            _log.debug("got response in callback: " + response);
          }
          if (!(response instanceof Set)) {
            String errorString = "Unexpected community response class:"
              + response.getClass().getName() + " - Should be a Community";
            _log.error(errorString);
            throw new RuntimeException(errorString);
          }
          tt.cancel();
          listener.getResponse((Set) response);
        }
      };

    String filter = "(Role=" + role +")";
      _threadService.schedule(tt, COMMUNITY_WARNING_TIMEOUT,
                              COMMUNITY_WARNING_TIMEOUT);
    Collection agents = 
      _cs.searchCommunity(communityName, filter, true, 
                          Community.AGENTS_ONLY, crl);

    if (agents != null) {
      tt.cancel();
      if (_log.isDebugEnabled()) {
        _log.debug("Got immediate response when looking for agents in role (" +
                   role + ") in community (" + communityName + ")");
      }
      HashSet set = new HashSet(agents);
      listener.getResponse(set);
    }
  }

  /**
   * Retrieves the security community for which this agent has the role
   * <tt>"Manager"</tt>.
   *
   * @param listener Callback receives at least one security community
   *                 in its getResponse.
   */
  public void 
    getManagedSecurityCommunity(CommunityServiceUtilListener listener) {
    getCommunity(SECURITY_COMMUNITY_TYPE, MANAGER_ROLE, listener);
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
            if (hasRole(community, MANAGER_ROOT)) {
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
        _log.debug( "returning as set is NULL");
      }
      return contains;
    }
    if(set.isEmpty()) {
      if (_log.isDebugEnabled()) {
        _log.debug( "returning as set is EMPTY");
      }
      return contains;
    }
    Iterator iter=set.iterator();
    Entity entity=null;
    while(iter.hasNext()){
      entity=(Entity)iter.next();
      if (_log.isDebugEnabled()) {
        _log.debug( "comparing : "+ entity.getName() + " with "+ agent);
      }
      if(entity.getName().trim().equals(agent)) {
        if (_log.isDebugEnabled()) {
          _log.debug(" Found : "+ entity.getName().trim() + " EQUALS" + agent);
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
    private TimerTask                    _timerTask;
    private boolean                      _allDone;

    public GetCommunity(CommunityServiceUtilListener listener, 
                        TimerTask timerTask,
                        String communityType,
                        String role) {
      _communityType = communityType;
      _role          = role;
      _listener      = listener;
      _timerTask     = timerTask;
    }

    public void communityChanged(CommunityChangeEvent event) {
      if (_allDone) {
        _cs.removeListener(this);
        return;
      }
      if (event.getType() != event.ADD_COMMUNITY &&
          event.getType() != event.ENTITY_ATTRIBUTES_CHANGED &&
          event.getType() != event.COMMUNITY_ATTRIBUTES_CHANGED &&
          event.getType() != event.ADD_ENTITY) {
        return; // not a change we care about
      }

      Community community = event.getCommunity();
      if (!isCommunityType(community, _communityType)) {
        if (_log.isDebugEnabled()) {
          _log.debug(community.getName() + " is not of type " + 
                     _communityType);
        }
        return;
      }

      if (_log.isDebugEnabled()) {
        _log.debug("community change: " + 
                   event.getChangeTypeAsString(event.getType()) +
                   ", " +
                   event.getWhatChanged());
      }

      if (hasRole(community, _role)) {
        // found it!
        _allDone = true;
        _timerTask.cancel();
        _cs.removeListener(this);
        _listener.getResponse(Collections.singleton(community));
        return;
      }
      if (_log.isDebugEnabled()) {
        _log.debug(_agent + " does not have role (" + _role + 
                   ") in community (" + community.getName() + ")");
      }
    }

    public String getCommunityName() {
      return null; // all MY communities
    }
  };

  private class GetAgent implements CommunityChangeListener {
    private String                       _communityType;
    private CommunityServiceUtilListener _listener;
    private TimerTask                    _timerTask;
    private String                       _role;
    private boolean                      _allDone;

    public GetAgent(CommunityServiceUtilListener listener, 
                    TimerTask timerTask,
                    String communityType,
                    String role) {
      _communityType = communityType;
      _listener = listener;
      _timerTask = timerTask;
      _role = role;
    }

    public void communityChanged(CommunityChangeEvent event) {
      if (_allDone) {
        _cs.removeListener(this);
        return;
      }
      if (event.getType() != event.ADD_COMMUNITY &&
          event.getType() != event.ENTITY_ATTRIBUTES_CHANGED &&
          event.getType() != event.COMMUNITY_ATTRIBUTES_CHANGED &&
          event.getType() != event.ADD_ENTITY) {
        return; // not a change we care about
      }

      Community community = event.getCommunity();
      if (!isCommunityType(community, _communityType)) {
        if (_log.isDebugEnabled()) {
          _log.debug(community.getName() + " is not of type " + 
                     _communityType);
        }
        return;
      }

      if (_log.isDebugEnabled()) {
        _log.debug("community change: " + 
                   event.getChangeTypeAsString(event.getType()) +
                   ", " +
                   event.getWhatChanged());
      }

      // Now while I understand that if the CommunityService is telling
      // me about this community, I must be a member, I don't trust it.
      // I'll check the membership.
      if (!hasRole(community, MEMBER_ROLE)) {
        if (_log.isDebugEnabled()) {
          _log.debug(_agent + " is not really part of (" + 
                     community.getName() + ") yet");
        }
        return;
      }
      Set set = community.search("(Role=" + _role + ")", 
                                 Community.AGENTS_ONLY);
      if (set.isEmpty()) {
        if (_log.isDebugEnabled()) {
          _log.debug("There are no members of role (" + _role +
                     ") in community (" + 
                     community.getName() + ") yet");
        }
        return;
      }
      _timerTask.cancel();
      _allDone = true;
      _cs.removeListener(this);
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

  private class WarnTimerTask extends TimerTask {
    private String _warning;
    private String _found;
    private long   _startTime = System.currentTimeMillis();

    public WarnTimerTask(String warning, String found) {
      _warning = warning;
      _found    = found;
    }

    public void run() {
      if (_log.isWarnEnabled()) {
        _log.warn(_warning + ": " + elapsedTime());
      }
    }

    public boolean cancel() {
      if (super.cancel()) {
        if (_log.isInfoEnabled()) {
          _log.info(_found + ": " + elapsedTime());
        }
        return true;
      } 
      return false;
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
  }

  private class ResultListener implements CommunityResponseListener {
    TimerTask                    _tt;
    CommunityServiceUtilListener _listener;
    CommunityChangeListener      _changeListener;
    String                       _role;

    public ResultListener(CommunityServiceUtilListener listener,
                          TimerTask warningTask,
                          CommunityChangeListener changeListener) {
      _tt = warningTask;
      _listener = listener;
      _changeListener = changeListener;
    }

    public ResultListener(CommunityServiceUtilListener listener,
                          TimerTask warningTask,
                          CommunityChangeListener changeListener,
                          String role) {
      _tt = warningTask;
      _listener = listener;
      _changeListener = changeListener;
      _role = role;
    }

    public void getResponse(CommunityResponse resp) {
      if (resp.getStatus() == resp.SUCCESS) {
        Object response = resp.getContent();

        if (!(response instanceof Set)) {
          String errorString = "Unexpected community response class:"
            + response.getClass().getName() + " - Should be a Set";
          _log.error(errorString);
          throw new RuntimeException(errorString);
        }
        Set set = (Set) response;
        if (_role != null) {
          set = withRole(set, _role);
        }
        if (!set.isEmpty()) {
          _listener.getResponse(set);
          _tt.cancel();
          return;
        }
      }

      // didn't find any appropriate community... start a listener
      _cs.addListener(_changeListener);
    }

  }
}
