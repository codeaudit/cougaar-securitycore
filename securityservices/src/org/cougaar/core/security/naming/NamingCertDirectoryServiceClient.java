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

package org.cougaar.core.security.naming;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.services.util.WhitePagesUtil;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.Callback;
import org.cougaar.core.service.wp.Cert;
import org.cougaar.core.service.wp.Response;
import org.cougaar.core.service.wp.WhitePagesService;
import org.cougaar.core.thread.Schedulable;

import java.net.URI;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import sun.security.x509.X500Name;

public class NamingCertDirectoryServiceClient {
  private LoggingService log;
  private ServiceBroker sb;
  private WhitePagesService _whitePagesService;
  private Hashtable _certCache = new Hashtable();
  private boolean _nodeupdated = false;
  private ThreadService _threadService;

  private int _multiply = 0;

  /**
   * This class only handles updating cert directly to naming
   */
  public NamingCertDirectoryServiceClient(ServiceBroker serviceBroker) {
    sb = serviceBroker;

    log = (LoggingService)
      sb.getService(this,
                    LoggingService.class,
                    null);

    if (log.isDebugEnabled()) {
      log.debug("Adding service listener for naming service :");
    }
    sb.addServiceListener(new MyServiceAvailableListener());

    _threadService=(ThreadService)sb.getService(this,ThreadService.class, null);

    String multiplyString = System.getProperty("org.cougaar.core.security.repeat_wp_rebind", null);
    try {
      _multiply = Integer.parseInt(multiplyString);
    } catch (Exception ex) {}
    if (log.isDebugEnabled()) {
      log.debug("naming entry will be repeated " + _multiply + " times to increase cert entry size");
    }
  }

  /**
   */
  public boolean updateCert(CertificateEntry certEntry) throws Exception {
    X509Certificate c = (X509Certificate)certEntry.getCertificate();
    String dname = c.getSubjectDN().getName();
    String cname = new X500Name(dname).getCommonName();

    // node cert need to be there before anything else can be published

    if (!_nodeupdated) {
      if (!cname.equals(NodeInfo.getNodeName())) {
        if (log.isDebugEnabled()) {
          log.debug("storing " + dname
                    + " before node cert registers to naming");
        }

        _certCache.put(dname, certEntry);
        return false;
      }
      else {
        _nodeupdated = true;

        if (log.isDebugEnabled()) {
          log.debug("updating other cert entries now node cert is created.");
        }
        updateCertEntryFromCache();
      }
    }
    if (_whitePagesService == null) {
      if (log.isDebugEnabled()) {
        log.debug("Naming service is not yet available, storing to cache.");
      }
      _certCache.put(dname, certEntry);
      return false;
    }

    updateCertEntry(certEntry);
    return true;
  }

  private void setNamingService() {
    if (_whitePagesService == null) {
      _whitePagesService = (WhitePagesService)
	sb.getService(this, WhitePagesService.class, null);
      updateCertEntryFromCache();
    }
  }

  private void setThreadService() {
    if (_threadService == null) {
      _threadService = (ThreadService)
	sb.getService(this, ThreadService.class, null);
    }
  }

  private void updateCertEntryFromCache() {
    if (!_nodeupdated) {
      if (log.isDebugEnabled()) {
        log.debug("update cert from cache: need to wait until node is enabled");
      }
      return;
    }
    if (_whitePagesService == null) {
      if (log.isDebugEnabled()) {
        log.debug("update cert from cache: need to wait until white pages is available");
      }
      return;
    }

    synchronized (_certCache) {
      for (Iterator it = _certCache.values().iterator(); it.hasNext(); ) {
        CertificateEntry cachedEntry = (CertificateEntry)it.next();
        if (log.isDebugEnabled()) {
          log.debug("updating " + cachedEntry.getCertificate().getSubjectDN()
                    + " after node cert updated in naming.");
        }
        try {
          updateCertEntry(cachedEntry);
        } catch (Exception ex) {
          //log.warn("Failed to update naming: ", ex);
          return;
        }
      }
    }
    _certCache.clear();
  }

  private void updateCertEntry(final CertificateEntry certEntry) throws Exception {
    X509Certificate c = (X509Certificate)certEntry.getCertificate();
    final String dname = c.getSubjectDN().getName();
    final String cname = new X500Name(dname).getCommonName();

    if (_whitePagesService == null) {
      log.warn("Cannot get white page service.");
      throw new Exception("Naming service is not available yet.");
    }

    if (log.isDebugEnabled()) {
      log.debug("updating NS for " + dname);
    }

    /** Callback to handle White page response.
     */
    Callback callback = new Callback() {
	/** Handle a WhitePagesService response. */
	public void execute(Response res) {
	  NamingCertEntry entry = null;

	  if (log.isDebugEnabled()) {
	    log.debug("Class name:" + res.getResult().getClass().getName());
	  }

	  AddressEntry ael = ((Response.Get)res).getAddressEntry();

	  if (ael != null) {
	    Cert cert = ael.getCert();
	    if (cert instanceof NamingCertEntry) {
	      entry = (NamingCertEntry)cert;
	      if (log.isDebugEnabled()) {
		log.debug("Cert type found in naming, updating");
	      }
	    }
	    else {
	      if (log.isDebugEnabled()) {
		log.debug("Different Cert type in naming, replacing");
	      }
	    }
	  }

	  List dnList = new ArrayList();
	  List certList = new ArrayList();
	  if (entry == null) {
	    if (log.isDebugEnabled()) {
	      log.debug("Creating new NamingCertEntry to update naming");
	    }
	    dnList.add(dname);            
	    certList.add(certEntry);
	  }
	  else {
	    dnList = entry.getDNList();
	    if (!dnList.contains(dname)) {
	      dnList.add(dname);
	    }

	    certList = entry.getEntries();
	    boolean found = false;
	    PublicKey pubKey = certEntry.getCertificate().getPublicKey();
	    for (int i = 0; i < certList.size(); i++) {
	      CertificateEntry acertEntry = (CertificateEntry)certList.get(i);
	      if (acertEntry.getCertificate().getPublicKey().equals(pubKey)) {
		// duplicate entry
		certList.set(i, certEntry);
		found = true;
	      }
	      break;
	    }
	    if (!found) {
	      certList.add(certEntry);
	    }
	  }


          for (int i = 0; i < _multiply; i++) {
            certList.add(certEntry);
          }
	  entry = new NamingCertEntry(dnList, certList);

          if (log.isDebugEnabled()) {
            log.debug("updated entry will be " + entry.toString() + " with hash code " + entry.hashCode());
          }
	  //entry.addEntry(dname, certEntry, true);

//	  if (ael == null) {
	    URI certURI = URI.create("cert://"+cname);
	    ael = AddressEntry.getAddressEntry(
	      cname,
	      WhitePagesUtil.WP_CERTIFICATE_TYPE,
	      certURI,
	      entry);
//	  }

	  // Cannot invoke wp.rebind() from within a Callback
	  // So create a thread to do the job.
          Schedulable rebindThread =
	    _threadService.getThread(this,
				    new RebindThread(cname, ael),
				    "CertRebindThread");
	  rebindThread.start();
	}
      };

    _whitePagesService.get(cname,
			  WhitePagesUtil.WP_CERTIFICATE_TYPE,
			  callback);
  }

  private class RebindThread implements Runnable {
    private String cname;
    private AddressEntry ael;
    private NamingCertEntry entry;

    public RebindThread(String cn, AddressEntry a) {
      cname = cn;
      ael = a;
    }

    public void run() {
      Callback callback = new Callback() {
	  /** Handle a WhitePagesService response. */
	  public void execute(Response res) {
	    if ( ((Response.Bind)res).didBind() ) {
	      // naming bug: naming service is enabled before
	      // naming thread is created so there is a problem
	      // updating naming even though naming service is available
	      // need to wait until we successfully updated naming
	      // for an entry (should happen after agents registers.
	      if (!_certCache.isEmpty()) {
		updateCertEntryFromCache();
	      }
	      if (log.isDebugEnabled()) {
		log.debug("Successfully updated naming: " + cname);
	      }
	    }
	    else {
	      if (log.isInfoEnabled()) {
		log.info("Unable to update naming: " + cname);
	      }
	    }
	  }
	};

      _whitePagesService.rebind(ael, callback);
    }
  }

  private class MyServiceAvailableListener implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      if(org.cougaar.core.service.wp.WhitePagesService.class.isAssignableFrom(sc)) {
	log.debug("Naming Service is now available");
        setNamingService();
      }
      else if (org.cougaar.core.service.ThreadService.class.isAssignableFrom(sc)) {
	log.debug("Thread Service is now available");
        setThreadService();
      }
    }
  }
}
