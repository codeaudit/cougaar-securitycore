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

import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.SimpleMessageAttributes;
import org.cougaar.mts.base.DestinationLink;
import org.cougaar.mts.base.DestinationLinkDelegateImplBase;
import org.cougaar.mts.base.ReceiveLink;
import org.cougaar.mts.base.ReceiveLinkDelegateImplBase;
import org.cougaar.mts.base.SendQueue;
import org.cougaar.mts.base.SendQueueDelegateImplBase;
import org.cougaar.mts.std.MessageProtectionAspect;
import org.cougaar.mts.std.AttributedMessage;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;

import java.util.Iterator;
import java.util.List;
import java.util.Hashtable;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * This class adds the necessary
 */
public class MessageProtectionAspectImpl extends MessageProtectionAspect {
// public class MessageProtectionAspectImpl extends StandardAspect {
  private static SendQueue _sendQ;
  private KeyRingService _keyRing;
  private LoggingService _log;
  private EncryptionService _crypto;
  private int              _plmsgcounter = 0;
  private static final int _warnCount    = 100;

  public static final String NODE_LINK_PRINCIPAL = 
    "org.cougaar.core.security.nodeLinkPrincipal";
  public static final String TARGET_LINK = 
    "org.cougaar.core.security.target.link";

  public static final String SIGNATURE_NEEDED = 
    "org.cougaar.core.security.crypto.sign";
  public static final String SENDING_PRINCIPAL =
    "org.cougaar.core.security.crypto.sending_principal";
  public static final String NEW_CERT = 
    "org.cougaar.core.security.crypto.newcert";


  static SendQueue getSendQueue() {
    return _sendQ;
  }

  public void load() {
    super.load();
    _keyRing = (KeyRingService)
      getServiceBroker().getService(this, KeyRingService.class, null);
    _crypto = (EncryptionService)
      getServiceBroker().getService(this, EncryptionService.class, null);
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
    } else if (type == ReceiveLink.class) {
      return new RefreshCertRecieveLinkDelegate((ReceiveLink) delegatee);
    }

    return delegate;
  }

  // Delgate on Deliverer (sees incoming messages)
  public class RefreshCertRecieveLinkDelegate
    extends ReceiveLinkDelegateImplBase {
    public RefreshCertRecieveLinkDelegate(ReceiveLink link) {
      super(link);
    }

    public MessageAttributes deliverMessage(AttributedMessage msg) {
      Object sign = msg.getAttribute(SIGNATURE_NEEDED);
      if (sign != null) {
        String source = msg.getOriginator().toAddress();
        String target = msg.getTarget().toAddress();
        if (_plmsgcounter++ > _warnCount && _log.isInfoEnabled()) {
          _log.info("Another " + _warnCount + " ProtectionLevel messages received");
          _plmsgcounter = 0;
        }
        boolean signMessage;
        if (sign instanceof Boolean) {
          signMessage = ((Boolean) sign).booleanValue();
        } else {
          signMessage = Boolean.valueOf(sign.toString()).booleanValue();
        }
        if (_log.isInfoEnabled()) {
          _log.info("Got a message from " + source +
                    " to " + (signMessage? "start" : "stop") + 
                    " signing messages sent from " + target);
        }
        if (signMessage) {
          _crypto.setSendNeedsSignature(target, source);
        } else {
          try {
            Hashtable certs = _keyRing.findCertPairFromNS(target, source);
            if (certs != null) {
              X509Certificate cert = (X509Certificate) certs.get(source);
              _crypto.removeSendNeedsSignature(target, 
                                               source, 
                                               cert);
            }
          } catch (Exception e) {
            _log.warn("Can't remove signature requirement for agent pair " +
                      target + ", " + source + ": " + e, e);
          }
        }
        MessageAttributes meta = new SimpleMessageAttributes();
        meta.setAttribute(MessageAttributes.DELIVERY_ATTRIBUTE,
                          MessageAttributes.DELIVERY_STATUS_DROPPED);
        return meta;
      }

      Object cert = msg.getAttribute(NEW_CERT);
      if (cert != null) {
        // Just refresh the LDAP, it is easier than modifying the certificate
        // in the cache. Perhaps a performance improvement later?
        if (_log.isInfoEnabled()) {
          _log.info("Got a certificate change message from " + 
                    msg.getOriginator().toAddress());
        } // end of if (_log.isInfoEnabled())
        
        List certs = _keyRing.findCert(msg.getOriginator().toAddress(), 
                                       _keyRing.LOOKUP_FORCE_LDAP_REFRESH | 
                                       _keyRing.LOOKUP_LDAP | 
                                       _keyRing.LOOKUP_KEYSTORE );
	ProtectedMessageOutputStream.
	    clearCertCache(msg.getTarget().toAddress(),
			   msg.getOriginator().toAddress());
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
                          MessageAttributes.DELIVERY_STATUS_DROPPED);
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
        }
      }
      System.out.println("Adding remote reference: " + remoteRef);
      System.out.println("Destination: " + getDestination());
      System.out.println("Protocol Class: " + getProtocolClass());
      */
      if (remoteRef != null) {
        attrs.setAttribute(TARGET_LINK, new TargetLinkRef(remoteRef));
      }
      super.addMessageAttributes(attrs);
    }
  }


  private static class TargetLinkRef implements java.io.Serializable {
    private int              _hashCode;
    private transient Object _ref;
    public TargetLinkRef(Object obj) {
      _ref = obj;
      _hashCode = _ref.toString().hashCode();
    }

    public String toString() {
      return _ref.toString();
    }

    public boolean equals(Object obj) {
      if (obj instanceof TargetLinkRef) {
        return ((TargetLinkRef) obj)._ref == _ref;
      }
      return false;
    }

    public int hashCode() { return _hashCode; }
  }
}
