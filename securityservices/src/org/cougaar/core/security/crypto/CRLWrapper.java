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

package org.cougaar.core.security.crypto;

import java.io.*;
import java.util.*;
import java.security.cert.*;
import java.security.Principal;
import java.security.PrivateKey;

import sun.security.x509.*;



public class CRLWrapper 
{
  private X509CRL crl;
  private String dnname;
  // private CertificateCache certCache;
  
  // private boolean debug = false;

  public CRLWrapper(String dn)//,CertificateCache certcache)
  {
    this.dnname=dn;
    this.crl=null;
    
  }
  public CRLWrapper(String dn ,X509CRL certcrl)
  {
    this.dnname=dn;
    this.crl=certcrl;
    
  }
  public void setCRL( X509CRL CRL)
  {
    crl=CRL;
  }
  public X509CRL getCRL() {
    return crl;
  }
 

 
}

