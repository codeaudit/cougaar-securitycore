/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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


import org.cougaar.core.service.MessageProtectionService;

import org.cougaar.core.mts.*;
import java.security.*;
import java.security.cert.*;
import javax.security.auth.*;
import java.io.*;
import java.util.Iterator;
import java.util.List;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.security.services.crypto.KeyRingService;

/**
 * This class adds the necessary
 */
public class MessageProtectionAspectImpl extends MessageProtectionAspect {
// public class MessageProtectionAspectImpl extends StandardAspect {
  private static SendQueue _sendQ;
  private KeyRingService _keyRing;
  private LoggingService _log;

  public static final String NODE_LINK_PRINCIPAL = "org.cougaar.core.security.nodeLinkPrincipal";
  public static final String TARGET_LINK = "org.cougaar.core.security.target.link";

  static SendQueue getSendQueue() {
    return _sendQ;
  }

  public void load() {
    super.load();
    _keyRing = (KeyRingService)
      getServiceBroker().getService(this, KeyRingService.class, null);
    _log = (LoggingService)
      getServiceBroker().getService(this, LoggingService.class, null);
  }

  public Object getDelegate(Object delegatee, Class type) {
    Object delegate = super.getDelegate(delegatee, type);
    Object paramDelegate = delegate;
    if (paramDelegate == null) {
      paramDelegate = delegatee;
    }

    if (type == SendQueue.class) {
      _sendQ = new CertificateSendQueueDelegate((SendQueue) paramDelegate);
      delegate = _sendQ;
    } else if (type == DestinationLink.class) {
      delegate =
        new ProtectionDestinationLink((DestinationLink) paramDelegate);
    }

    return delegate;
  }

  // aspect implementation: reverse linkage (receive side)
  public Object getReverseDelegate(Object delegate, Class type) {
    if (type == ReceiveLink.class) {
      return new RefreshCertRecieveLinkDelegate((ReceiveLink) delegate);
    } else {
      return super.getReverseDelegate(delegate, type);
    }
  }

  // Delgate on Deliverer (sees incoming messages)
  public class RefreshCertRecieveLinkDelegate
    extends ReceiveLinkDelegateImplBase {
    public RefreshCertRecieveLinkDelegate(ReceiveLink link) {
      super(link);
    }

    public MessageAttributes deliverMessage(AttributedMessage msg) {
      Principal p = org.cougaar.core.security.ssl.KeyRingSSLServerFactory.getPrincipal();
//       System.out.println("delivering message: " + msg + ", " + p);
      if (p != null) {
        msg.setAttribute(NODE_LINK_PRINCIPAL, p.getName());
      }
      Object cert = msg.getAttribute(MessageProtectionServiceImpl.NEW_CERT);
      if (cert != null) {
        // Just refresh the LDAP, it is easier than modifying the certificate
        // in the cache. Perhaps a performance improvement later?
        if (_log.isInfoEnabled()) {
          _log.info("Got a certificate change message from " + msg.getOriginator().toAddress());
        } // end of if (_log.isInfoEnabled())
        
        List certs = _keyRing.findCert(msg.getOriginator().toAddress(), 
                                       _keyRing.LOOKUP_FORCE_LDAP_REFRESH | 
                                       _keyRing.LOOKUP_LDAP | 
                                       _keyRing.LOOKUP_KEYSTORE );
        if (_log.isDebugEnabled()) {
          _log.debug("Got " + certs.size() + " certificates");
          Iterator iter = certs.iterator();
          while (iter.hasNext()) {
            CertificateStatus cs = (CertificateStatus) iter.next();
            if (cs.getCertificate().equals(cert)) {
              _log.debug("The certificate is in the list");
              break;
            } // end of if (cs.getCertificate().equals(cert))
          } // end of while (iter.hasNext())
        } // end of if (_log.isDebugEnabled())
        
        // now just drop the message
        MessageAttributes meta = new SimpleMessageAttributes();
        meta.setAttribute(MessageAttributes.DELIVERY_ATTRIBUTE,
                          MessageAttributes.DELIVERY_STATUS_DELIVERED);
        return meta;
      } else {
        // deliver other messages as normal
        return super.deliverMessage(msg);
      } 
    }
  }

  public static class CertificateSendQueueDelegate 
    extends SendQueueDelegateImplBase {
    public CertificateSendQueueDelegate(SendQueue queue) {
      super(queue);
    }
    
    public synchronized void sendMessage(AttributedMessage msg) {
      super.sendMessage(msg);
    }
  }

  private static class ProtectionDestinationLink
    extends DestinationLinkDelegateImplBase {
    public ProtectionDestinationLink(DestinationLink link) {
      super(link);
    }

    public void addMessageAttributes(MessageAttributes attrs) {
      Object remoteRef = getRemoteReference();
      /*
      if (remoteRef instanceof MT) {
        try {
          MT mt = (MT) remoteRef;
          System.out.println("remote address = " + mt.getMessageAddress());
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
      System.out.println("Adding remote reference: " + remoteRef);
      System.out.println("Destination: " + getDestination());
      System.out.println("Protocol Class: " + getProtocolClass());
      */
      if (remoteRef != null) {
        attrs.setAttribute(TARGET_LINK, remoteRef.toString());
      }
      super.addMessageAttributes(attrs);
    }
  }


}
