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


import org.cougaar.core.mts.AttributedMessage;
import org.cougaar.core.mts.DestinationLink;
import org.cougaar.core.mts.DestinationLinkDelegateImplBase;
import org.cougaar.core.mts.StandardAspect;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;

import org.cougaar.core.security.services.crypto.KeyRingService;

import java.util.List;

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
      // Get address of target and lookup white pages to see if
      // certificate exists.
      String targetAddress = message.getTarget().toAddress();

      List certs = null;
      int nbcerts = 0;
      try {
	certs = _keyRing.findCert(targetAddress, 
				  _keyRing.LOOKUP_FORCE_LDAP_REFRESH | 
				  _keyRing.LOOKUP_LDAP | 
				  _keyRing.LOOKUP_KEYSTORE );
      }
      catch (Exception e) {
        // Nothing to do
      }

      if (certs == null || certs.size() == 0) {
	ret = Integer.MAX_VALUE; // infinity
      }
      else {
	ret = super.cost(message);
        nbcerts = certs.size();
      }
      if (_log.isDebugEnabled()) {
	_log.debug("Cost for " + targetAddress
		  + " is " + ret + " - " + nbcerts
                  + " certificates found - "
                  + super.getProtocolClass().getName());
      }
      return ret;
    }
  }
}
