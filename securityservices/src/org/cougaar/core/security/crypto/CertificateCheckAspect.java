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
 * Created on September 12, 2001, 10:55 AM
 */
 
package org.cougaar.core.security.crypto;


import org.cougaar.mts.std.AttributedMessage;
import org.cougaar.mts.base.DestinationLink;
import org.cougaar.mts.base.DestinationLinkDelegateImplBase;
import org.cougaar.mts.base.StandardAspect;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.mts.base.LoopbackLinkProtocol;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.MessageFailureEvent;
import org.cougaar.core.security.monitoring.plugin.MessageFailureSensor;

import org.cougaar.core.security.services.crypto.KeyRingService;

import java.util.List;
import java.util.Map;
import java.util.Iterator;

/**
 * Intercept the "cost()" call to each of the LinkProtocol's.
 *
 * The interface between the DestinationQueue and the DestinationLink asks
 * each LinkProtocol for the "cost" to send to an Agent and then picks
 * the smallest cost. The LinkProtocols use this call to lookup the Agent's
 * address in the WP. If Agent address is not available, it returns a cost
 * of "infinite". If all the DestinationLinks have "infinite" cost,
 * the message is retried later. The retry is silent. 

 * We do the check for the certificate at this point, before all the
 * serialization happens.  If the certificate is unavailable, the aspect
 * returns "infinite". When the certificate becomes available, the cost() call
 * is passed down to the LinkProtocol.
 */
public class CertificateCheckAspect
  extends StandardAspect
{
  private KeyRingService _keyRing;
  private LoggingService _log;
  /**
   * Specifies if the aspect should block local loop messages when there is no
   * valid certificate.
   */
  private boolean        _checkLocalMessages = true;

  public void load() {
    super.load();
    _keyRing = (KeyRingService)
      getServiceBroker().getService(this, KeyRingService.class, null);
    _log = (LoggingService)
      getServiceBroker().getService(this, LoggingService.class, null);
  }

  /*
  public Object getDelegate(Object delegatee, Class type) {
    if (_log.isDebugEnabled()) {
      _log.debug("Delegatee " + delegatee
		 + " type " + type.getName());
    }
    if (type == DestinationLink.class) {
      DestinationLink link = (DestinationLink) delegatee;
      return new ProtectedDestinationLink(link);
    } else {
      return null;
    }
  }
  */

  public Object getReverseDelegate(Object object, Class type) {
    if (_log.isDebugEnabled()) {
      _log.debug("ReverseDelegate " + object
                 + " type " + type.getName());
    }
    if (type == DestinationLink.class) {
      DestinationLink link = (DestinationLink) object;
      return new ProtectedDestinationLink(link);
    } else {
      return null;
    }
  }

  private class ProtectedDestinationLink
    extends DestinationLinkDelegateImplBase 
  {
    private DestinationLink _delegatee;

    ProtectedDestinationLink(DestinationLink delegatee) {
      super(delegatee);
      _delegatee = delegatee;
    }

    /**
     * This method returns a simple measure of the cost of sending the
     * given message via the associated transport. Only called during
     * processing of messages in DestinationQueueImpl. */
    public int cost(AttributedMessage message) {
      int ret = 0;
      boolean drop = false;

      // Get address of target and lookup white pages to see if
      // certificate exists.
      String targetAddress = message.getTarget().toAddress();
      String originatorAddress = message.getOriginator().toAddress();

      int nbcertsTarget = 0;
      int nbcertsOriginator = 0;
      try {
	List certsTarget = _keyRing.findCert(targetAddress);
	List certsOriginator = _keyRing.findCert(originatorAddress);
	// findCert looks up in the cache but does not go to the naming
	// service if it is not in the cache. We should ask the KeyRingService 
	// to actually go to the naming service and find the certificates, if any.
	// This is what the findCertPairFromNS() function does.
	// The certificate will not be returned immediately, but at least we have
	// a chance to get the certificate the next time CertificateCheckAspect
	// is invoked for the same message.
	// There is no need to do it for the originator, as it is a local
	// certificate.
	if (certsTarget == null || certsTarget.size() == 0) {
	  _keyRing.findCertPairFromNS(targetAddress, targetAddress);
	}
	else {
	  nbcertsTarget = certsTarget.size();
	}

	if (certsOriginator == null || certsOriginator.size() == 0) {
	  _keyRing.findCertPairFromNS(originatorAddress, originatorAddress);
	}
	else {
	  nbcertsOriginator = certsOriginator.size();
	}
      }
      catch (Exception e) {
	if (_log.isDebugEnabled()) {
	  _log.debug("Certificate not found yet:" + e);
	}
      }
      if (nbcertsTarget == 0 || nbcertsOriginator == 0) {
	if (super.getProtocolClass().equals(LoopbackLinkProtocol.class)
	    && !_checkLocalMessages) {
	  // Do not drop if this is a local message.
	  ret = super.cost(message);
	}
	else {
	  checkBadCerts(originatorAddress, nbcertsOriginator, 
			targetAddress, nbcertsTarget);
	  ret = Integer.MAX_VALUE; // infincty
	  drop = true;
	}
      }
      else {
	ret = super.cost(message);
      }
      if (_log.isDebugEnabled()) {
	String s = " ["
	  + originatorAddress + " (" + nbcertsOriginator + " certs) -> "
	  + targetAddress + " (" + nbcertsTarget + " certs) - cost: " + ret
	  + " - " + super.getProtocolClass().getName() + "]";
	if (drop == true) {
	  s = "Dropping " + message + s;
	}
	else {
	  if (ret == Integer.MAX_VALUE) {
	    s = super.getProtocolClass().getName() +
	      " cannot send message to " + targetAddress;
	  }
	  else {
	    s = "OK" + s;
	  }
	}
	_log.debug(s);
      }
      return ret;
    }

    /** Publish an IDMEF message, if necesary
     */
    private void checkBadCerts(String originatorAddress, int nbcertsOriginator,
			       String targetAddress, int nbcertsTarget) {
      int targetAllCerts = 0;
      int targetBadCerts = 0;
      int originatorAllCerts = 0;
      int originatorBadCerts = 0;
      boolean publishIdmef = false;

      List targetAll = _keyRing.findCert(targetAddress,
		 KeyRingService.LOOKUP_LDAP | KeyRingService.LOOKUP_KEYSTORE,
					 false);
      if (targetAll != null && targetAll.size() > 0) {
	targetAllCerts = targetAll.size();
	Iterator it = targetAll.iterator();
	while (it.hasNext()) {
	  CertificateStatus st = (CertificateStatus)it.next();
	  if (CertificateTrust.CERT_TRUST_REVOKED_CERT.
	      equals(st.getCertificateTrust()) ||
	    CertificateTrust.CERT_TRUST_NOT_TRUSTED.
	      equals(st.getCertificateTrust())) {
	    targetBadCerts++;
	  }
	}
      }
      List originatorAll = _keyRing.findCert(originatorAddress,
	       KeyRingService.LOOKUP_LDAP | KeyRingService.LOOKUP_KEYSTORE,
               false);
      if (originatorAll != null && originatorAll.size() > 0) {
	originatorAllCerts = originatorAll.size();
	Iterator it = originatorAll.iterator();
	while (it.hasNext()) {
	  CertificateStatus st = (CertificateStatus)it.next();
	  if (CertificateTrust.CERT_TRUST_REVOKED_CERT.
	      equals(st.getCertificateTrust()) ||
	      CertificateTrust.CERT_TRUST_NOT_TRUSTED.
	      equals(st.getCertificateTrust())) {
	    originatorBadCerts++;
	  }
	}
      }
      String s = "";
      
      if ((nbcertsTarget == 0) && (targetAllCerts > 0) &&
	  (targetBadCerts == targetAllCerts)) {
	// The target does not have valid certificates, but it has
	// invalid certificates.
	s = s + "All target certificates are invalid (" +
	  targetAllCerts + "). ";
	publishIdmef = true;
      }
      if ((nbcertsOriginator == 0) && (originatorAllCerts > 0) &&
	  (originatorBadCerts == originatorAllCerts)) {
	// The originator does not have valid certificates, but it has
	// invalid certificates.
	s = s + "All source certificates are invalid (" +
	  originatorAllCerts + ")";
	publishIdmef = true;
      }
      if (publishIdmef) {
	publishMessageFailure(originatorAddress, targetAddress,
			      MessageFailureEvent.INVALID_CERTIFICATE,
			      s);
      }
    }

    /**
     * publish a message failure idmef alert
     */
    private void publishMessageFailure(String source, String target,
                                       String reason, String data) {
      FailureEvent event = new MessageFailureEvent(source, target,
                                                   reason, data);
      MessageFailureSensor.publishEvent(event);
    }
  }
}
