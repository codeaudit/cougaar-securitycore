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


/*
 * Created on Jul 28, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.cougaar.core.security.services.yp;


import org.cougaar.core.component.Service;
import org.cougaar.core.security.services.wp.ProtectedRequest;
import org.cougaar.yp.YPMessage;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;


/**
 * Service for YP servers and clients to use  for protecting and verifying  YP
 * messages
 *
 * @author ttschampel
 */
public interface YellowPagesProtectionService extends Service {
  /**
   * Signs the request and wraps the request with the certificate chain used
   * for signing
   *
   * @param agent - The agent making the request
   * @param message - the yellow page message
   *
   * @return the wraped request object
   */
  public ProtectedRequest protectMessage(String agent, YPMessage message)
    throws CertificateException, GeneralSecurityException;


  /**
   * Installs and verifies the signing certificate
   *
   * @param agent - The agent making the request
   * @param request - the request object
   */
  public void verfifyMessage(String agent, ProtectedRequest request)
    throws CertificateException;
}
