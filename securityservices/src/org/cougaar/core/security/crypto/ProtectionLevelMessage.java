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
