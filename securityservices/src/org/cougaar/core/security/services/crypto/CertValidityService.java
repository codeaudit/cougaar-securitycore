/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.services.crypto;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.crypto.CertValidityListener;

public interface CertValidityService extends Service {
// will make the certificate if it is not present, this should only be used for local agents!
  public void addValidityListener(CertValidityListener listener);

  public void updateCertificate(String commonName);

  public void invalidate(String cname);

// only listen when cert becomes invalid, does not check and make cert, there is a possibility that the agent is NOT local
// used for messaging or ssl
  public void addInvalidateListener(CertValidityListener listener);

// only listens when a cert becomes available, does not check make the cert if it is not available. there is a possibility that the agent is NOT local
// used for name server certificate update
  public void addAvailabilityListener(CertValidityListener listener);

// check if the (local) agent has been revoked
  public boolean isInvalidated(String commonName);
}

