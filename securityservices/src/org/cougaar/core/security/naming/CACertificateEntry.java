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


package org.cougaar.core.security.naming;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.util.DateUtil;

public class CACertificateEntry extends CertificateEntry
  implements Serializable {

  private byte []derEncodedCRL=null;
  private String lastModifiedTime;
 
  public CACertificateEntry(X509Certificate cert,
                            CertificateRevocationStatus status, 
                            CertificateType certtype, X509CRL crl,
                            String modifiedTime) throws CRLException {
    super(cert,status,certtype);
    if(crl!=null) {
      derEncodedCRL=crl.getEncoded();
    }
    this.lastModifiedTime=modifiedTime;
  }

  /**
   * Public accessor method for retrieving the CRL.
   */
  public X509CRL getCRL() { 
    X509CRL crl =null;
    if(derEncodedCRL!=null) {
      try {
	InputStream inStream = new ByteArrayInputStream(derEncodedCRL);
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
  
  public byte[] getEncodedCRL() {
    if(derEncodedCRL!=null) {
      return derEncodedCRL;
    }
    return null;
  }

  /**
   * Public accessor method for setting  the CRL.
   */
  public void setCRL(X509CRL crl)throws CRLException {
    if(crl!=null) {
      derEncodedCRL=crl.getEncoded();
    }
    lastModifiedTime=DateUtil.getCurrentUTC();
  }

  public String getLastModifiedTimeStamp() {
    if(lastModifiedTime!=null) {
      return lastModifiedTime;
    }
    return null;
  }
  
  public String toString() {
    StringBuffer buff=new StringBuffer();
    buff.append(super.toString());
    if(getLastModifiedTimeStamp()!=null) {
      buff.append(" Last Modified :"+ getLastModifiedTimeStamp());
    }
    else {
      buff.append(" Last Modified :  ");
    }
   return  buff.toString();
  }
}
