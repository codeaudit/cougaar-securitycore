/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */
package org.cougaar.core.security.dataprotection;

// Cougaar core infrastructure
import org.cougaar.core.component.Service;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceListener;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.Entity;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.WhitePagesService;

// security services
import org.cougaar.core.security.policy.PersistenceManagerPolicy;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.PersistenceMgrPolicyService;
import org.cougaar.core.security.services.util.WhitePagesUtil;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.CommunityServiceUtil;

// java
import java.net.URI;
import java.util.*;
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
  // to get the agent address entries
  private WhitePagesService _wps;
  // community and white pages service listener
  private ServiceListener _serviceListener;
  // my community
  private String _myCommunity;
  // list of persistence manager policies
  private List _policies;
  private List _agents;
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

  public PersistenceMgrPolicyServiceImpl(ServiceBroker sb, String community) {
    _serviceBroker = sb;
    _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    _keyRing = (KeyRingService)sb.getService(this, KeyRingService.class, null);
    _cs = (CommunityService)sb.getService(this, CommunityService.class, null);
    _wps = (WhitePagesService)sb.getService(this, WhitePagesService.class, null);
    if(_cs == null || _wps == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Starting service listener.");
      }
      registerServiceListener();
    }
    _myCommunity = community;
    _policies = new ArrayList();
    _agents = new ArrayList();
    _debug = _log.isDebugEnabled();
    // default to every 2 mins (120 secs)
    long period = 120000;
    try {
      SecurityPropertiesService sps = (SecurityPropertiesService)
      sb.getService(this, SecurityPropertiesService.class, null);
      String prop = sps.getProperty(SecurityPropertiesService.PM_SEARCH_PERIOD, "120");  // default to 120 secs
      period = Long.parseLong(prop) * 1000; // in msecs
    }
    catch(NumberFormatException nfe) {
      _log.error("error parsing persistence manager lookup period");
    }
    // schedule task to lookup persistence managers from community service
    (new Timer()).schedule(new PersistenceMgrSearchTask(), 0, period);
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
          _log.debug("community service is now available");
          _cs = (CommunityService)
            ae.getServiceBroker().getService(this, CommunityService.class, null);
        }
        if(org.cougaar.core.service.wp.WhitePagesService.class.isAssignableFrom(sc)) {
        //else if(ae.getService() == WhitePagesService.class) {
          _log.debug("white pages service is now available");
          _wps = (WhitePagesService)
            ae.getServiceBroker().getService(this, WhitePagesService.class, null);
        }
      }
    };
    _serviceBroker.addServiceListener(sal);
    _serviceListener = sal;
  }

  // remove service listener for community and white pages service
  private void removeServiceListener() {
    if(_serviceListener != null) {
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

  private void addPolicy(PersistenceManagerPolicy policy) {
    if(_debug) {
      _log.debug("adding PersistenceManagerPolicy: " + policy);
    }
    synchronized(_policies) {
      _policies.add(policy);

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
  class PersistenceMgrSearchTask extends TimerTask  {
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
            configureCommunity((Set) response);
	  }
	};

      String filter = "(& (CommunityType="+
	CommunityServiceUtil.SECURITY_COMMUNITY_TYPE + ") (Role=" + PM_ROLE +") )";
      Collection communities = _cs.searchCommunity(null, filter, true, Community.AGENTS_ONLY, crl);
      if (communities != null) {
        configureCommunity((Set) communities);
      }
    }

    private void configureCommunity(Set communities) {
      Iterator it = communities.iterator();
      while (it.hasNext()) {
        processPersistenceMgrEntry((Entity) it.next());
      }
    }

    private void processPersistenceMgrEntry(Entity manager) {
      String agent = manager.getName();
      if(!_agents.contains(agent)) {
	AddressEntry entry = null;
	try {
	  // look up the agent's info in the white pages
	  entry = _wps.get(agent, WhitePagesUtil.WP_HTTP_TYPE);
	  if(_debug) {
	    _log.debug("address entry = " + entry);
	  }
	}
	catch(Exception e) {
	  // if an error occurs ignore this persistence manager
	  _log.error("unable to get " + agent +
		     " info from the white pages.", e);
	  return;
	}
	if (entry == null) {
	  if(_debug) {
	    _log.debug("address entry is null for : " + agent);
	  }
	  return;
	}

	// construct the url for this persistence manager
	URI uri = entry.getURI();
	String servletUrl = uri + PM_SERVLET_URI;
	// get all DNs associated with this agent
	Collection dns = null;
        try {
          dns = _keyRing.findDNFromNS(agent);
        }
        catch (Exception iox) {
          if (_log.isDebugEnabled()) {
            _log.debug("Failed to get PM name " + agent);
          }
          return;
        }
	Iterator i = dns.iterator();
	while(i.hasNext()) {
	  X500Name name = (X500Name)i.next();
	  addPolicy(createPolicy(servletUrl, name.getName()));
	}
	// only add the agent if haven't already
	if(dns.size() > 0) {
	  _agents.add(agent);
	}
      } // if(!_agents.contains(pm))
    }

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
}
