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

package org.cougaar.core.security.naming;

import org.cougaar.core.security.crypto.CertificateRevocationStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.util.DateUtil;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

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


}
