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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;



public class CRLWrapper  implements Serializable
{
  private byte []derencodedCRL=null;
  private String dnname;
  private String certDirectoryURL;
  private int certDirectoryType;
  private String lastModifiedTime;
  // private CertificateCache certCache;
  
  // private boolean debug = false;
  
  public CRLWrapper(String dn) {
    this.dnname=dn;
    this.derencodedCRL=null;
    this.certDirectoryURL=null;
    this.certDirectoryType=-1;
    this.lastModifiedTime=null;
  }

  public CRLWrapper(String dn,String directoryUrl,int directoryType)//,CertificateCache certcache)
    {
      this.dnname=dn;
      this.derencodedCRL=null;
      this.certDirectoryURL=directoryUrl;
      this.certDirectoryType=directoryType;
      this.lastModifiedTime=null;
    
    }
  public CRLWrapper(String dn ,byte[] certcrl ,String modifiedTimestamp)
    {
      this.dnname=dn;
      this.derencodedCRL=certcrl;
      this.certDirectoryURL=null;
      this.certDirectoryType=-1;
      lastModifiedTime=modifiedTimestamp;
    }
  public void setCRL( byte [] encodedcrl)
    {
      derencodedCRL=encodedcrl;
    }
  public X509CRL getCRL() {
    X509CRL crl =null;
    if(derencodedCRL!=null){
      try {
	InputStream inStream = new ByteArrayInputStream(derencodedCRL);
	CertificateFactory cf = CertificateFactory.getInstance("X.509");
	crl = (X509CRL)cf.generateCRL(inStream);
	inStream.close();
      }
      catch (Exception exp){
        return crl;
      }
    }
    return crl;
  }

  public String getDN () {
    return dnname;
  }
  public String getCertDirectoryURL(){
    return certDirectoryURL;
  }
  public int getCertDirectoryType(){
    return certDirectoryType;
  }
  
  public void setLastModifiedTimestamp(String tstamp) {
    lastModifiedTime=tstamp;
  }
  
  public String getLastModifiedTimestamp() {
    return lastModifiedTime;
  }

   
}

