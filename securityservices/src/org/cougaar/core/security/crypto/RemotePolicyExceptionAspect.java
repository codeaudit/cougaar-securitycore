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
import java.security.PrivilegedAction;
import java.security.AccessController;

import java.net.SocketException;

import java.util.Iterator;
import java.util.List;

import org.cougaar.core.mts.MessageAttributes;

import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.KeyRingService;

import org.cougaar.core.service.LoggingService;

import org.cougaar.mts.base.CommFailureException;
import org.cougaar.mts.base.DestinationLink;
import org.cougaar.mts.base.DestinationLinkDelegateImplBase;
import org.cougaar.mts.base.MisdeliveredMessageException;
import org.cougaar.mts.base.NameLookupException;
import org.cougaar.mts.base.StandardAspect;
import org.cougaar.mts.base.UnregisteredNameException;
import org.cougaar.mts.std.AttributedMessage;


/**
 * This catches exceptions from the remote party and tries to repair policy
 * problems.
 */
public class  RemotePolicyExceptionAspect
  extends StandardAspect 
{
  private LoggingService _log;
  private EncryptionService _crypto;
  private KeyRingService _keyRing;


  public void load() 
  {
    super.load();
    _log = (LoggingService)
      getServiceBroker().getService(this, LoggingService.class, null);
    AccessController.doPrivileged(new PrivilegedAction() {
      public Object run() {
        _crypto = (EncryptionService)
           getServiceBroker().getService(this, EncryptionService.class, null);
        _keyRing = (KeyRingService)
           getServiceBroker().getService(this, KeyRingService.class, null);
        return null;
      }
    });
  }

  public Object getDelegate(Object delegatee, Class type) 
  {
    if (type == DestinationLink.class) {
      return new RemotePolicyExceptionLink((DestinationLink) delegatee);
    } else { return null; }
  }

  private class RemotePolicyExceptionLink
    extends DestinationLinkDelegateImplBase
  {
    DestinationLink _link;

    public RemotePolicyExceptionLink(DestinationLink link)
    {
      super(link);
      _link = link;
    }

    public MessageAttributes forwardMessage(AttributedMessage msg) 
      throws UnregisteredNameException, 
             NameLookupException, 
             CommFailureException,
             MisdeliveredMessageException
    {
      try {
	return _link.forwardMessage(msg);
      } catch (CommFailureException e) {
        Throwable rootCause = getRootCause(e);
        if (_log.isDebugEnabled()) {
          _log.debug("working on exception " + e + 
                     " with root cause " + rootCause);
        }
        if (rootCause instanceof IncorrectProtectionException) {
          IncorrectProtectionException ipe 
            = (IncorrectProtectionException) rootCause;
          if (ipe.reason() == CryptoPolicyService.CRYPTO_SHOULD_SIGN) {
            startSigning(msg);
            return _link.forwardMessage(msg);
          }
        } else if (rootCause instanceof SenderUsingInvalidCertException) {
          SenderUsingInvalidCertException suice
            = (SenderUsingInvalidCertException) rootCause;
          updateCerts(msg, suice.getCertificate());
          throw e;
        } else if (rootCause instanceof SocketException) {
          updateCerts(msg, null);
          startSigning(msg);
          throw e;
        }
        throw e;
      }
    }

    private void startSigning(AttributedMessage msg)
    {
      String source = msg.getOriginator().toAddress();
      String target = msg.getTarget().toAddress();
      _crypto.setSendNeedsSignature(source, target);
      if (_log.isDebugEnabled()) {
        _log.debug("Exception lets me know I should sign messages from " +
                   source + " to " + target);
      }
    } 

    private  void updateCerts(AttributedMessage msg, X509Certificate cert)
    {
      // Just refresh the LDAP, it is easier than modifying the 
      // certificate in the cache. Perhaps a performance 
      // improvement later?
      if (_log.isInfoEnabled()) {
        _log.info("Got a certificate change message from " + 
                  msg.getOriginator().toAddress());
      }
        
      List certs = _keyRing.findCert(msg.getOriginator().toAddress(), 
                                     KeyRingService.LOOKUP_FORCE_LDAP_REFRESH | 
                                     KeyRingService.LOOKUP_LDAP | 
                                     KeyRingService.LOOKUP_KEYSTORE );
      ProtectedMessageOutputStream.
        clearCertCache(msg.getTarget().toAddress(),
                       msg.getOriginator().toAddress());
      if (_log.isDebugEnabled() && cert != null) {
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
    }

    private Throwable getRootCause(Exception exc)
    {
      Throwable root = exc;
      for (Throwable inner = exc.getCause(); 
           inner != null; 
           inner = inner.getCause()) {
        root = inner;
      }
      return root;
    }
  }
}
