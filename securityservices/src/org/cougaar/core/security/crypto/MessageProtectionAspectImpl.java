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

 
package org.cougaar.core.security.crypto;

import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.security.PrivilegedAction;
import java.security.AccessController;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;

import org.cougaar.core.agent.TopologyService;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.SimpleMessageAttributes;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.mts.base.ReceiveLink;
import org.cougaar.mts.base.ReceiveLinkDelegateImplBase;
import org.cougaar.mts.base.SendQueue;
import org.cougaar.mts.std.AttributedMessage;
import org.cougaar.mts.std.MessageProtectionAspect;

/**
 * This class adds the necessary
 */
public class MessageProtectionAspectImpl extends MessageProtectionAspect {
// public class MessageProtectionAspectImpl extends StandardAspect {
  private static SendQueue _sendQ;
  private static Long      _incarnation_no;
  private TopologyService _ts;
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

  static  Long getIncarnation()
  {
    return _incarnation_no;
  }


  public void load() {
    super.load();
    _log = (LoggingService)
      getServiceBroker().getService(this, LoggingService.class, null);
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        _keyRing = (KeyRingService)
           getServiceBroker().getService(this, KeyRingService.class, null);
        _crypto = (EncryptionService)
           getServiceBroker().getService(this, EncryptionService.class, null);
        _ts = (TopologyService) 
          getServiceBroker().getService(this, TopologyService.class, null);
        if (_ts != null) {
          _incarnation_no = new Long(_ts.getIncarnationNumber());
          getServiceBroker().releaseService(this, TopologyService.class, _ts);
        } else {
          if (_log.isInfoEnabled()) {
            _log.info("No incarnation number available yet");
          }
          getServiceBroker().addServiceListener(new TopologyServiceAvailableListener());
        }
        return null;
      }
    });
  }

  public Object getDelegate(Object delegatee, Class type) {
    Object delegate = super.getDelegate(delegatee, type);
    Object paramDelegate = delegate;
    if (paramDelegate == null) {
      paramDelegate = delegatee;
    }

    if (type == SendQueue.class) {
      _sendQ = (SendQueue) paramDelegate;
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
      Object contents = msg.getRawMessage();
      if (contents instanceof StopSigningMessage) {
        String source = msg.getOriginator().toAddress();
        String target = msg.getTarget().toAddress();
        if (_plmsgcounter++ > _warnCount && _log.isInfoEnabled()) {
          _log.info("Another " + _warnCount + " ProtectionLevel messages received");
          _plmsgcounter = 0;
        }
        if (_log.isInfoEnabled()) {
          _log.info("Got a message from " + source +
                    " to stop signing messages sent from " + target);
        }
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

  private class TopologyServiceAvailableListener
    implements ServiceAvailableListener
  {
    public void serviceAvailable(ServiceAvailableEvent sae)
    {
      ServiceBroker sb = sae.getServiceBroker();
      Class         sc = sae.getService();
      if (TopologyService.class.isAssignableFrom(sc)) {
        if (_log.isDebugEnabled()) {
          _log.debug("Getting toplogy service");
        }
        TopologyService tps = (TopologyService)
            sb.getService(this, TopologyService.class, null);
        if (tps != null) {
          _incarnation_no = new Long(tps.getIncarnationNumber());
          if (_log.isInfoEnabled()) {
            _log.info("Incarnation number available");
          }
          sb.releaseService(this, TopologyService.class, tps);
          sb.removeServiceListener(this);
        }
      }
    }
  }
}
