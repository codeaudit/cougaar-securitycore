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
