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

