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
import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;

import java.security.cert.X509Certificate;

public class ProtectionLevelMessage extends Message {
  private boolean         _signatureNeeded;
  private int             _messageType;
  private X509Certificate _cert;

  public int SIGNATURE_NEEDED   = 1;
  public int CERTIFICATE_CHANGE = 2;

  public ProtectionLevelMessage(MessageAddress source, MessageAddress target,
                                boolean signatureNeeded) {
    super(source, target);
    _signatureNeeded = signatureNeeded;
    _messageType = SIGNATURE_NEEDED;
  }

  public ProtectionLevelMessage(MessageAddress source, MessageAddress target,
                                X509Certificate newCert) {
    super(source, target);
    _cert = newCert;
    _messageType = CERTIFICATE_CHANGE;
  }

  public boolean isSignatureNeeded() {
    return _signatureNeeded;
  }

  public int getMessageType() {
    return _messageType;
  }

  public X509Certificate getCertificate() {
    return _cert;
  }

  public boolean equals(Object o) {
    if (o instanceof ProtectionLevelMessage) {
      ProtectionLevelMessage pmsg = (ProtectionLevelMessage) o;
      if (_messageType != pmsg._messageType) {
        return false;
      }
      if (_messageType == SIGNATURE_NEEDED) {
        return _signatureNeeded == pmsg._signatureNeeded;
      }
      if (_cert == null) {
        return pmsg._cert == null;
      }
      return _cert.equals(pmsg._cert);
    }
    return false;
  }
  
  public int hashCode() {
    int hashCode = _messageType;
    if (_signatureNeeded) {
      hashCode = ~hashCode;
    }
    if (_cert != null) {
      hashCode ^= _cert.hashCode();
    }
    return hashCode;
  }
}
