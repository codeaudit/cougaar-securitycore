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

package org.cougaar.core.security.dataprotection;

// Cougaar core infrastructure
import java.security.PrivilegedAction;
import java.security.AccessController;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceListener;
import org.cougaar.core.security.policy.PersistenceManagerPolicy;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.PersistenceMgrAvailListener;
import org.cougaar.core.security.services.util.PersistenceMgrPolicyService;
import org.cougaar.core.security.services.util.WhitePagesUtil;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.Callback;
import org.cougaar.core.service.wp.Response;
import org.cougaar.core.service.wp.WhitePagesService;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.mts.MessageAddress;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.HashSet;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import sun.security.x509.X500Name;

/**
 * The PersistenceMgrPolicyService queries the community service for agents
 * with the "PersistenceManager" role, and caches the search results.
 */
public class PersistenceMgrPolicyServiceImpl
  implements PersistenceMgrPolicyService {

  private ServiceBroker _serviceBroker;
  private LoggingService _log;
  // key ring service used to determine the DN(s) of the persistence manager(s)
  private KeyRingService _keyRing;
  // community service used to lookup persistence manager(s)
  private CommunityService _cs;
  // The ThreadService
  private ThreadService _threadService=null;
  // to get the agent address entries
  private WhitePagesService _wps;
  // community and white pages service listener
  private ServiceListener _serviceListener;
  // event service
  private EventService _eventService;
  // Address of local node
  private MessageAddress _localNode = null;
  // list of persistence manager policies
  private List _policies;

  private Set _agentsBeingSearched = new HashSet();

  // debug flag
  private boolean _debug;

  // this is the uri of the persistence manager key recovery servlet
  private static String PM_SERVLET_URI = "/KeyRecoveryServlet";
  // this is the role of a persistence manager
  private static String PM_ROLE = "PersistenceManager";

  // need to inform listeners new pm arrived, so that they can protect their
  // old keys with it, some listeners are not protected with any PM keys
  // because there are none available when they start persisting.
  private Hashtable pmListeners = new Hashtable();

  public PersistenceMgrPolicyServiceImpl(ServiceBroker sb) {
    _serviceBroker = sb;
    _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        _keyRing = (KeyRingService)_serviceBroker.getService(this, KeyRingService.class, null);
        return null;
      }
    });
    _cs = (CommunityService)sb.getService(this, CommunityService.class, null);
    _wps = (WhitePagesService)sb.getService(this, WhitePagesService.class, null);
    _eventService = (EventService)sb.getService(this, EventService.class, null);    if (_eventService == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Event Service unavailable - spawning listener");
      }
      sb.addServiceListener(new EventServiceAvailableListener());
    }

    NodeIdentificationService nis = (NodeIdentificationService)
      sb.getService(this, NodeIdentificationService.class, null);
    if (nis == null) {
      if (_log.isWarnEnabled()) {
        _log.warn("Unable to getNodeIdentificationService ");
      }
      throw new RuntimeException("PersistenceMgrPolicyServiceImpl. No NodeIdentificationService");
    }
    _localNode = nis.getMessageAddress();
    sb.releaseService(this, NodeIdentificationService.class, nis);
    _threadService = (ThreadService)sb.getService(this, ThreadService.class, null);

    _policies = new ArrayList();
    _debug = _log.isDebugEnabled();

    if(_cs == null || _wps == null || _threadService == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Starting service listener...");
      }
      registerServiceListener();
    }
    else {
      addCommunityListener();
    }

    if (_todo != null) {
      _log.warn("testing community service " + _todo);
    }
  }

  /*
  private void startTimerTask() {
    // default to every 2 mins (120 secs)
    long period = 120000;
    try {
      SecurityPropertiesService sps = (SecurityPropertiesService)
      _serviceBroker.getService(this, SecurityPropertiesService.class, null);
      String prop = sps.getProperty(SecurityPropertiesService.PM_SEARCH_PERIOD, "120");  // default to 120 secs
      period = Long.parseLong(prop) * 1000; // in msecs
    }
    catch(NumberFormatException nfe) {
      _log.error("error parsing persistence manager lookup period");
    }
    // schedule task to lookup persistence managers from community service
    (new Timer()).schedule(new PersistenceMgrSearchTask(), 0, period);
  }
  */

  static String _todo = System.getProperty("org.cougaar.core.security.dataprotection.communityTest");
  private void addCommunityListener() {
    if (_log.isDebugEnabled()) {
      _log.debug("addCommunityListener");
    }

    // scenario 1: do not add listener 
    if (_todo != null && _todo.equals("1")) {
      return;
    }

    _cs.addListener(new CommunityChangeListener() {
      public String getCommunityName() {
        return null;
      }

      public void communityChanged(CommunityChangeEvent event) {
        if (_todo != null && _todo.equals("2")) {
          return;
        }

        Community community = event.getCommunity();
        try {
          Attributes attrs = community.getAttributes();
          Attribute attr = attrs.get("CommunityType");
          if (attr != null) {
            for (int i = 0; i < attr.size(); i++) {
              Object type = attr.get(i);
              if (type.equals(CommunityServiceUtil.SECURITY_COMMUNITY_TYPE)) {
                if (_log.isDebugEnabled()) {
                  _log.debug("Got community: " + community.getName());
                }
                // changes that might add agent
                if (event.getType() == CommunityChangeEvent.ADD_COMMUNITY
                  || event.getType() == CommunityChangeEvent.ADD_ENTITY) {
                  setupRole(community);
                }
                // change that might remove agent
                if (event.getType() == CommunityChangeEvent.REMOVE_ENTITY
                  || event.getType() == CommunityChangeEvent.REMOVE_COMMUNITY) {
                  checkRemovedRole(community);
                }
              }
            }
          }
        } catch (NamingException e) {
          throw new RuntimeException("This should never happen");
        }

      }
    });
  }

  private void checkRemovedRole(Community community) {
    String communityName = community.getName();
    String filter = "(Role=" + PM_ROLE + ")";
    Set mgrAgents = community.search(filter, Community.AGENTS_ONLY);
    Iterator it = mgrAgents.iterator();
    if (_log.isDebugEnabled()) {
      _log.debug("checkRemovedRole for " + communityName
        + " - " + mgrAgents.size() + "  manager agents");
      _log.debug("Community: " + community.toXml());
    }
    List pmAgents = new ArrayList();
    while (it.hasNext()) {
      Entity entity = (Entity) it.next();
      pmAgents.add(entity.getName());
    }

    // check policies to see if those agents still there
    PersistenceManagerPolicy [] policies = getPolicies();
    for (int i = 0; i < policies.length; i++) {
      String pmAgent = policies[i].pmDN;

      if (!pmAgents.contains(pmAgent)) {
        if (_log.isInfoEnabled()) {
          _log.info("Removing PM " + pmAgent + " from list, entity has been removed from community.");
        }
        synchronized (_policies) {
          _policies.remove(policies[i]);
        }

        // removing PM but leave the keys already encrypted with it intact.
        // for recovery new PM keys will be used as well as old PM keys
        for (Enumeration en = pmListeners.elements(); en.hasMoreElements(); ) {
          PersistenceMgrAvailListener listener =
            (PersistenceMgrAvailListener)en.nextElement();
          listener.removePM(policies[i]);
        }
         
      }
    }
  }


  private void setupRole(Community community) {
    String communityName = community.getName();
    String filter = "(Role=" + PM_ROLE + ")";
    Set mgrAgents = community.search(filter, Community.AGENTS_ONLY);
    Iterator it = mgrAgents.iterator();
    if (_log.isDebugEnabled()) {
      _log.debug("setupRole for " + communityName
	+ " - " + mgrAgents.size() + "  manager agents");
      _log.debug("Community: " + community.toXml());
    }
    while (it.hasNext()) {
      Entity entity = (Entity) it.next();
      processPersistenceMgrEntry(entity);
    }
  }


  /**
   * get the latest Persistence Manager Policies
   */
  public PersistenceManagerPolicy [] getPolicies() {
    PersistenceManagerPolicy [] policies = null;
    synchronized(_policies) {
      policies = (PersistenceManagerPolicy [])
        _policies.toArray(new PersistenceManagerPolicy[0]);
    }
    return policies;
  }

  // register community and white pages service listener
  private void registerServiceListener() {
    ServiceAvailableListener sal = new ServiceAvailableListener() {

      public void serviceAvailable(ServiceAvailableEvent ae) {
        Class sc = ae.getService();
        //if(ae.getService() == CommunityService.class) {
        if(org.cougaar.core.service.community.CommunityService.class.isAssignableFrom(sc)) {
          if (_log.isDebugEnabled()) {
            _log.debug("community service is now available");
          }
          if (_cs == null) {
            _cs = (CommunityService)
              ae.getServiceBroker().getService(this, CommunityService.class, null);
          }
        }
        else if(org.cougaar.core.service.wp.WhitePagesService.class.isAssignableFrom(sc)) {
        //else if(ae.getService() == WhitePagesService.class) {
          if (_log.isDebugEnabled()) {
            _log.debug("white pages service is now available");
          }
          if (_wps == null) {
            _wps = (WhitePagesService)
              ae.getServiceBroker().getService(this, WhitePagesService.class, null);
          }
        }
        else if (org.cougaar.core.service.ThreadService.class.isAssignableFrom(sc)) {
          if (_log.isDebugEnabled()) {
            _log.debug("Thread Service is now available");
          }
          if (_threadService == null) {
            _threadService = (ThreadService)
               ae.getServiceBroker().getService(this, ThreadService.class, null);
          }
        }
        if (_cs != null && _wps != null && _threadService != null) {
          // All required services are available.
          if (_log.isDebugEnabled()) {
            _log.debug("All required services are now available");
          }
          removeServiceListener();
          addCommunityListener();
        }
      }
    };
    _serviceBroker.addServiceListener(sal);
    _serviceListener = sal;
  }

  // remove service listener for community and white pages service
  private void removeServiceListener() {
    if(_serviceListener != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Removing service listener...");
      }
      _serviceBroker.removeServiceListener(_serviceListener);
    }
  }

  private PersistenceManagerPolicy createPolicy(String url, String dn) {
    PersistenceManagerPolicy policy = new PersistenceManagerPolicy();
    policy.pmType = "URL"; // only type that is supported
    policy.pmUrl = url;
    policy.pmDN = dn;
    return policy;
  }

  private void addPolicy(PersistenceManagerPolicy policy, String pmName) {
    if(_debug) {
      _log.debug("adding PersistenceManagerPolicy: " + policy);
    }
    synchronized(_policies) {
      if (_policies.contains(policy)) {
        if(_log.isDebugEnabled()) {
          _log.debug("Policy already added: " + policy);
        }
        return;
      }
      _policies.add(policy);
      if (_eventService.isEventEnabled()) {
        String s = "PersistenceManager ";
        s += "ADD ";
        s += "PM=";
        s += pmName;
        s += " Node=";
        s += _localNode.toAddress();
        if (_log.isInfoEnabled()) {
          _log.info(s);
        }
        _eventService.event(s);
      }
      for (Enumeration it = pmListeners.elements(); it.hasMoreElements(); ) {
        PersistenceMgrAvailListener listener =
          (PersistenceMgrAvailListener)it.nextElement();
        listener.newPMAvailable(policy);
      }
    }
  }

  public void addPMListener(String name, PersistenceMgrAvailListener listener) {
    pmListeners.put(name, listener);
  }

  /**
   * This task is searches for persistence managers and constructs
   * a PersistenceManagerPolicy for new persistence managers
   */
   /*
  class PersistenceMgrSearchTask extends TimerTask  {

  *** This is commented out. If you see this, then please change this
  *** code to use CommunityServiceUtil!

    // list of persistence managers
    private List _agents;
    public PersistenceMgrSearchTask() {
      _agents = new ArrayList();
    }

    private void searchPersistenceManagers() {
      CommunityResponseListener crl = new CommunityResponseListener() {
	  public void getResponse(CommunityResponse resp) {
	    Object response = resp.getContent();
	    if (!(response instanceof Set)) {
	      String errorString = "Unexpected community response class:"
		+ response.getClass().getName() + " - Should be a Set";
	      _log.error(errorString);
	      throw new RuntimeException(errorString);
	    }

            if (_log.isDebugEnabled()) {
              _log.debug("Got community response");
            }
            configureCommunity((Set) response);
	  }
	};

      String filter = "(& (CommunityType="+
	CommunityServiceUtil.SECURITY_COMMUNITY_TYPE + ") (Role=" + PM_ROLE +") )";
      if (_log.isDebugEnabled()) {
        _log.debug("searching PM " + filter);
      }

      Collection communities = _cs.searchCommunity(null, filter, true, Community.AGENTS_ONLY, crl);

      if (_log.isDebugEnabled()) {
        _log.debug("obtained community" + communities);
      }
      if (communities != null) {
        configureCommunity((Set) communities);
      }

    }

    private void configureCommunity(Set communities) {
      if (_log.isDebugEnabled()) {
        _log.debug("Got community with size " + communities.size());
      }
      Iterator it = communities.iterator();
      while (it.hasNext()) {
        processPersistenceMgrEntry((Entity) it.next());
      }
    }
    */

  private void processPersistenceMgrEntry(Entity manager) {
    String agent = manager.getName();
    
    if (_log.isDebugEnabled()) {
      _log.debug("processPersistenceMgrEntry: " + manager + " agent " + agent);
    }

    synchronized(_agentsBeingSearched) {
      if (!_agentsBeingSearched.contains(agent)) {
        _agentsBeingSearched.add(agent);
        lookupPMuri(agent, 0);
      }
      else {
        if (_log.isDebugEnabled()) {
          _log.debug("WP search for " + agent + " already in progress");
        }
      }
    }
  }

  private void lookupPMuri(final String pmName, final int sleepTime) {
        Schedulable wpThread = _threadService.getThread(this, new Runnable( ) {
          public void run() {
            try {
              // look up the agent's info in the white pages
              _wps.get(pmName, WhitePagesUtil.WP_HTTP_TYPE, new WpCallback(pmName));
            }
            catch(Exception e) {
              // if an error occurs ignore this persistence manager
              _log.error("unable to get " + pmName +
                         " info from the white pages.", e);
            }
          } // public void run()
        }, "PersistenceManagerUriWpLookup: " + pmName);
        if (_log.isDebugEnabled()) {
          _log.debug("Going to look up URI of PM=" + pmName + " in " + sleepTime + "ms...");
        }
        wpThread.schedule(sleepTime);
  }

  private class WpCallback
    implements Callback {
    /**
     * The name of the persistence manager agent.
    */
    private String _agent;
    /**
     * The time between each WP lookup retry.
     */
    private final int WP_LOOKUP_RETRY_PERIOD = 10 * 1000;

    public WpCallback(String agent) {
      _agent = agent;
    }
    public void execute(Response resp) {
      if (!(resp instanceof Response.Get)) {
        
	if (_log.isErrorEnabled()) {
	  _log.error("Unexpected response: " + resp.getClass().getName()
	    + " - Should be a Response.Get");
	  return;
	}
      }

      if (resp.isSuccess()) {
	AddressEntry entry = ((Response.Get) resp).getAddressEntry();
	if(_debug) {
	  _log.debug("address entry = " + entry);
	}

	if (entry == null) {
	  if(_debug) {
	    _log.debug("address entry is null for : " + _agent);
	  }
          lookupPMuri(_agent, WP_LOOKUP_RETRY_PERIOD);
	  return;
	}

	// construct the url for this persistence manager
	URI uri = entry.getURI();
	String servletUrl = uri + PM_SERVLET_URI;
	// get all DNs associated with this agent
	Collection dns = null;
	if (_log.isDebugEnabled()) {
	  _log.debug("Searching DN for " + _agent + "...");
	}
	try {
	  dns = _keyRing.findDNFromNS(_agent);
	}
	catch (Exception iox) {
	  if (_log.isDebugEnabled()) {
	    _log.debug("Failed to get PM name " + _agent + ". Reason: " + iox);
	  }
          lookupPMuri(_agent, WP_LOOKUP_RETRY_PERIOD);
	  return;
	}
	if (_log.isDebugEnabled()) {
	  _log.debug("Found " + dns.size() + " DN entries for " + _agent);
	}
	// only add the agent if haven't already
	if(dns.size() == 0) {
          if (_log.isDebugEnabled()) {
            _log.debug("No DN found for " + _agent);
          }
          lookupPMuri(_agent, WP_LOOKUP_RETRY_PERIOD);
          return;
	}
	Iterator i = dns.iterator();
	while(i.hasNext()) {
	  X500Name name = (X500Name)i.next();
          List certList = _keyRing.findCert(name, 
            KeyRingService.LOOKUP_LDAP | KeyRingService.LOOKUP_KEYSTORE, true);
          if (certList == null || certList.size() == 0) {
            if (_log.isInfoEnabled()) {
              _log.warn("Found PM entry for " + _agent + "in WP but no certificate!");
            }
            lookupPMuri(_agent, WP_LOOKUP_RETRY_PERIOD);
            return;
          }
	  addPolicy(createPolicy(servletUrl, name.getName()), _agent);
        }
	synchronized (_agentsBeingSearched) {
          if (_log.isDebugEnabled()) {
            _log.debug("Releasing search lock for " + _agent);
          }
          _agentsBeingSearched.remove(_agent);
	}
      }
      else {
        _log.warn("Response failed for " + _agent);
        lookupPMuri(_agent, WP_LOOKUP_RETRY_PERIOD);
      }
    }
  }


  private class EventServiceAvailableListener
    implements ServiceAvailableListener
  {
    public void serviceAvailable(ServiceAvailableEvent ae) 
    {
      if (ae.getService().equals(EventService.class)) {
        _eventService = (EventService) ae.getServiceBroker().
          getService(this, EventService.class, null);
        if (_eventService != null) {
          ae.getServiceBroker().removeServiceListener(this);
	  if (_log.isDebugEnabled()) {
	    _log.debug("Got event service");
	  }
        }
      }
    }
  }

    /*
    public void run() {
      // get a list of all security communities
      if(_cs == null || _wps == null) {
        if(_debug) {
          _log.debug("community service or white pages service is null!");
        }
        return;
      }
      searchPersistenceManagers();
    } // public void run()
  } // class PersistenceMgrSearchTask
  */
}
