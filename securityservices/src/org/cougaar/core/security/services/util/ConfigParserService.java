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


package org.cougaar.core.security.services.util;

import java.io.Serializable;
import java.io.File;
import sun.security.x509.*;
import org.w3c.dom.*;
import java.io.InputStream;

// Cougaar core infrastructure
import org.cougaar.core.component.Service;

// Cougaar core services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.crypto.PublicKeyEnvelope;
import org.cougaar.core.security.crypto.SecureMethodParam;

/** Service for parsing security services configuration files
 */
public interface ConfigParserService extends Service {

  File findPolicyFile(String policyfilename);

  /** The mode of operation
   * @return true if executing as a certificate authority
   *         false if executing as a standard Cougaar node
   */
  boolean isCertificateAuthority();

  //Document getConfigDocument();

  /** Get the node crypto policy
   */
  CaPolicy getCaPolicy(String aDN);

  void parsePolicy(InputStream policy, String fileName);
  SecurityPolicy[] getSecurityPolicies();
  SecurityPolicy[] getSecurityPolicies(Class policyClass);

  /** Get all the roles specified in the XML file
   */
  String[] getRoles();

  /** Get all the Certificate Authority X500 names specified
   *  in the XML file.
   */
  X500Name[] getCaDNs();

}

