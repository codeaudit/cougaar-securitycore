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



package org.cougaar.core.security.services.util;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.config.PolicyUpdateException;
import org.cougaar.core.security.policy.CaPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;

import java.io.InputStream;

import sun.security.x509.X500Name;

/** Service for parsing security services configuration files
 */
public interface ConfigParserService extends Service {

  InputStream findPolicyFile(String policyfilename);

  /** The mode of operation
   * @return true if executing as a certificate authority
   *         false if executing as a standard Cougaar node
   */
  boolean isCertificateAuthority();

  //Document getConfigDocument();

  /** Get the node crypto policy
   */
  CaPolicy getCaPolicy(String aDN);

  void parsePolicy(InputStream policy);
  SecurityPolicy[] getSecurityPolicies();
  SecurityPolicy[] getSecurityPolicies(Class policyClass);
 
  /** Get all the roles specified in the XML file
   */
  String[] getRoles();

  /** Get all the Certificate Authority X500 names specified
   *  in the XML file.
   */
  X500Name[] getCaDNs();

  void addSecurityPolicy(SecurityPolicy policy);
  void updateSecurityPolicy(SecurityPolicy policy) throws PolicyUpdateException;

}

