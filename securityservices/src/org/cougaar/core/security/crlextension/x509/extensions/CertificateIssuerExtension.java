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


package org.cougaar.core.security.crlextension.x509.extensions;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.util.Enumeration;

import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AttributeNameEnumeration;
import sun.security.x509.CertAttrSet;
import sun.security.x509.Extension;

public class CertificateIssuerExtension extends Extension
  implements CertAttrSet {
  
  private void encodeThis()
    throws IOException {
    if(issuerName == null || issuerName.isEmpty()) {
      super.extensionValue = null;
      return;
    }
    DerOutputStream deroutputstream = new DerOutputStream();
    try {
      issuerName.encode(deroutputstream);
    }
    catch(IOException generalnamesexception)  {
      generalnamesexception.printStackTrace();
      throw generalnamesexception;
    }
    super.extensionValue = deroutputstream.toByteArray();
  }

  public CertificateIssuerExtension(CougaarGeneralNames generalnames)
    throws IOException {
    issuerName = null;
    issuerName = generalnames;
    //System.out.println(" In constructor of CertificateIssuerExtension:");
    super.extensionId=new ObjectIdentifier(certIssuerOID);
    super.critical = false;
    encodeThis();
  }

  public CertificateIssuerExtension()  
    throws IOException {
    issuerName = null;
    super.extensionId=new ObjectIdentifier(certIssuerOID);
    super.critical = false;
    issuerName = new CougaarGeneralNames();
  }

  public CertificateIssuerExtension(Boolean boolean1, Object obj)
    throws IOException  {
    issuerName = null;
    super.extensionId =new ObjectIdentifier(certIssuerOID);
    super.critical = boolean1.booleanValue();
    int i = Array.getLength(obj);
    byte abyte0[] = new byte[i];
    for(int j = 0; j < i; j++)
      abyte0[j] = Array.getByte(obj, j);

    super.extensionValue = abyte0;
    DerValue dervalue = new DerValue(abyte0);
//    try {
      issuerName = new CougaarGeneralNames(dervalue);
//    }
//    catch(GeneralNamesException generalnamesexception){
//      throw new IOException("IssuerAlternativeNameExtension" + generalnamesexception.toString());
//    }
  }

  public String toString()  {
    if(issuerName == null)  {
      return "";
    } 
    else  {
      StringBuffer buffer=new StringBuffer(); 
      buffer.append( super.toString()); 
      buffer.append( "Certificate Issuer Name [\n" + issuerName.toString() + "]\n");
      return buffer.toString();
    }
  }

  public void set(String s, Object obj)
    throws IOException  {
    if(s.equalsIgnoreCase(ISSUERNAME))  {
      if(!(obj instanceof CougaarGeneralNames)) {
	throw new IOException("Attribute value should be of type GeneralNames.");
      }
      issuerName = (CougaarGeneralNames)obj;
    }
    else  {
      throw new IOException("Attribute name not recognized by CertAttrSet:certificateIssuer.");
    }
    encodeThis();
  }

  public Object get(String s)
    throws IOException {
    if(s.equalsIgnoreCase(ISSUERNAME))
      return issuerName;
    else
      throw new IOException("Attribute name not recognized by CertAttrSet:certificateIssuer.");
    
  }

  public void delete(String s)
    throws IOException {
    if(s.equalsIgnoreCase(ISSUERNAME))
      issuerName=null;
    else
      throw new IOException("Attribute name not recognized by CertAttrSet:certificateIssuer.");
    encodeThis();
  }

  public Enumeration getElements()  {
    AttributeNameEnumeration attributenameenumeration = new AttributeNameEnumeration();
    attributenameenumeration.addElement(ISSUERNAME);
    return attributenameenumeration.elements();
  }
  
  public void encode(OutputStream outputstream)
    throws IOException  {
    DerOutputStream deroutputstream = new DerOutputStream();
    if(super.extensionValue == null)
      {
	super.extensionId =new ObjectIdentifier("2.5.29.29");
	super.critical = false;
	encodeThis();
      }
    super.encode(deroutputstream);
    outputstream.write(deroutputstream.toByteArray());
  }
  
  public void decode(InputStream inputstream)
    throws IOException  {
    throw new IOException("Method not to be called directly.");
  }

  public String getName()  {
    return  "CertificateIssuer";
  }
  

  public static final String IDENT = "x509.info.extensions.CertificateIssuer";
  public final String certIssuerOID="2.5.29.29";  
  public static final String NAME ="CertificateIssuer";
  public static final String ISSUERNAME="certificateIssuer"; 
  private CougaarGeneralNames issuerName=null; 

  
}


