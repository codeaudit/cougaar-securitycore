/*
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
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
 */
package org.cougaar.core.security.util;

import java.io.*;
import java.util.*;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRL;
import java.security.cert.CertificateFactory;
import java.security.*;
import sun.security.x509.*;
import sun.security.util.*;
import java.lang.reflect.*;

import java.security.cert.CertificateException;
import java.security.cert.CRLException;


import org.cougaar.core.security.crlextension.x509.extensions.*;

public class CrlUtility {
   public static final String issuingdpointname="IssuingDistibutionPoint";



   public static CRLExtensions getExtensions(X509CRL crl) throws IOException {
    //Vector extension=new Vector();
    CRLExtensions extensions=new CRLExtensions();
    Set critSet =crl.getCriticalExtensionOIDs();
    boolean critical=true;
    boolean noncritical=false;
    String oid=null;
    DerInputStream dis=null;
    byte[]extensiondata=null;

    if (critSet != null && !critSet.isEmpty()) {
      for (Iterator i = critSet.iterator(); i.hasNext();) {
	oid = (String)i.next();
	String s1 = OIDMap.getName(new ObjectIdentifier(oid));
	extensiondata=crl.getExtensionValue(oid);
	dis=new DerInputStream(extensiondata);
	DerValue val=dis.getDerValue();
	byte[] byted=val.getOctetString();
	int ic = byted.length;
	Object obj = Array.newInstance(Byte.TYPE, ic);
	for(int j = 0; j < ic; j++)
	  Array.setByte(obj, j, byted[j]);
	try {
	  Class class1=OIDMap.getClass(new ObjectIdentifier(oid));
	  if(class1!=null) {
	    Class aclass[] = {
	      java.lang.Boolean.class, java.lang.Object.class
	    };
	    Constructor constructor = class1.getConstructor(aclass);
	    Object aobj[] = {
	      new Boolean(critical), obj
	    };
	    Extension  ext = (Extension)constructor.newInstance(aobj);
	    X509AttributeName x509attributename = new X509AttributeName(s1);
	    String s2 = x509attributename.getPrefix();
	    String s3;
	    if(s2.equalsIgnoreCase("x509"))  {
		int j = s1.lastIndexOf(".");
		s3 = s1.substring(j + 1);
	    } else
	      {
		s3 = s1;
	      }
            extensions.set(s3,ext);
	  }
	  else {
	    throw new IOException (" Cannot create Extension for oid :"+oid);
	  }
	}
	catch (Exception exp) {
	  throw new IOException (" Cannot create Extension for oid :"+oid +"  for following reason :"+exp.getMessage());
	}
      }
    }
    critSet =crl.getNonCriticalExtensionOIDs();
    if (critSet != null && !critSet.isEmpty()) {
      for (Iterator i = critSet.iterator(); i.hasNext();) {
	oid = (String)i.next();
	String s1 = OIDMap.getName(new ObjectIdentifier(oid));
	extensiondata=crl.getExtensionValue(oid);
	dis=new DerInputStream(extensiondata);
	DerValue val=dis.getDerValue();
	byte[] byted=val.getOctetString();
	int ic = byted.length;
	Object obj = Array.newInstance(Byte.TYPE, ic);
	for(int j = 0; j < ic; j++)
	  Array.setByte(obj, j, byted[j]);
	try {
	  Class class1=OIDMap.getClass(new ObjectIdentifier(oid));
	  if(class1!=null) {
	    Class aclass[] = {
	      java.lang.Boolean.class, java.lang.Object.class
	    };
	    Constructor constructor = class1.getConstructor(aclass);
	    Object aobj[] = {
	      new Boolean(noncritical), obj
	    };
	    Extension  ext = (Extension)constructor.newInstance(aobj);
	    extensions.set(s1,ext);
	  }
	  else {
            //throw new IOException (" Cannot create Extension for oid :"+oid);
	  }
	}
	catch (Exception exp) {
          continue;
	}
      }
    }
    return extensions;

  }
  

  public static X509CRL createEmptyCrl(String caDN, PrivateKey privatekey,String algorithm) throws 
    CRLException,NoSuchAlgorithmException, 
    InvalidKeyException, NoSuchProviderException, SignatureException ,IOException{
    X509CRLEntry [] crlentry=new X509CRLEntry[1];
    X500Name name=new X500Name(caDN);
    Calendar c = Calendar.getInstance();
    Date current=c.getTime();
    c.add(Calendar.HOUR_OF_DAY,1);
    Date next=c.getTime();
    X509CRLImpl crl=new X509CRLImpl(name,current,next,null);
     crl.sign(privatekey,algorithm);
    return crl;
  }


  public static X509CRL createCRL(X509Certificate caCert, X509CRL caCRL,
                                  X509Certificate clientCert,
                                  X509Certificate clientIssuerCert,
                                  PrivateKey caPrivateKey,
                                  String crlSignAlg ) 
    throws NoSuchAlgorithmException, InvalidKeyException,
    CertificateException, CRLException, NoSuchProviderException,
    SignatureException,IOException {
    
    
    PublicKey caPublicKey=caCert.getPublicKey();
    caCRL.verify(caPublicKey);
    Set crlentryset=caCRL.getRevokedCertificates();
    X509CRLEntry crlentry;
    Calendar calendar=Calendar.getInstance();
    Date current=calendar.getTime();
    calendar.add(Calendar.HOUR_OF_DAY,1);
    Date next =calendar.getTime();
    Vector crlentrys =new Vector();
    if((crlentryset!=null)&&(!crlentryset.isEmpty())) {
      Iterator i=crlentryset.iterator();
      for(;i.hasNext();) {
	crlentry=(X509CRLEntry)i.next();
	crlentrys.add(crlentry);
      }
    }
    crlentrys.trimToSize();
     
    X509CRLImpl crlimpl=null;
    X509CRLEntry[] crlentryarray=new X509CRLEntry[crlentrys.size()+1];
    crlentrys.copyInto(crlentryarray);
    
    PublicKey issuerPublicKey=clientIssuerCert.getPublicKey();
    String userDN=clientCert.getSubjectDN().getName();
    CRLExtensions  extensions=null;
    X509CRLEntryImpl crlentryimpl=null;
    try {
      extensions= getExtensions(caCRL);
    }
    catch ( IOException ioexp) {
      ioexp.printStackTrace();
      throw new IOException(ioexp.getMessage());
    }

    if(issuerPublicKey.equals(caPublicKey)) {
      crlentryimpl=new X509CRLEntryImpl(clientCert.getSerialNumber(),current);
      crlentryarray[crlentryarray.length-1]=crlentryimpl;
      if(extensions!=null) {
	crlimpl=
	  new X509CRLImpl(new X500Name(caCert.getSubjectDN().getName()),
			  current,next,crlentryarray,extensions);
      }
      else {
	crlimpl=
	  new X509CRLImpl(new X500Name(caCert.getSubjectDN().getName()),
			  current,next,crlentryarray);
      }
    }
    else {
      //boolean indirectcrl=isIndirectCRLset(crl);
      IssuingDistributionPointExtension idpext=null;
      if(extensions!=null) {
        idpext=getDistributionPointExtension(extensions);
      }
      if(idpext!=null) {
	Boolean indirectCRL=(Boolean)idpext.get(IssuingDistributionPointExtension.INDIRECT_CRL);
	if(!indirectCRL.booleanValue()) {
	  idpext.set(IssuingDistributionPointExtension.INDIRECT_CRL,new Boolean(true));
	  extensions.delete(issuingdpointname);
          extensions.set(idpext.getName(),idpext);
	}
      }
      else {
	if(extensions==null) {
          extensions=new CRLExtensions();
	}
	idpext=new  IssuingDistributionPointExtension (false,false,true);
	extensions.set(idpext.getName(),idpext);
      }
      //CRLExtensions crlext=new CRLExtensions();//CertificateIssuerExtension
      X500Name username=new X500Name(clientCert.getIssuerDN().getName());
      CougaarGeneralNames gns=	new  CougaarGeneralNames();
      gns.add(username);
      CertificateIssuerExtension cie=new CertificateIssuerExtension();
      CertificateIssuerExtension certificateext=new  CertificateIssuerExtension(gns);
      CRLExtensions crlentryext =new CRLExtensions();
      crlentryext.set(certificateext.getName(),certificateext);
      crlentryimpl=new X509CRLEntryImpl(clientCert.getSerialNumber(),current,crlentryext);
      crlentryarray[crlentryarray.length-1]=crlentryimpl;
      crlimpl=new X509CRLImpl(new X500Name(caCert.getSubjectDN().getName()),current,next,crlentryarray,extensions);
    }
    crlimpl.sign(caPrivateKey,crlSignAlg);
    
    return crlimpl;
    
  }

   public static IssuingDistributionPointExtension getDistributionPointExtension(CRLExtensions crlextensions) {

    IssuingDistributionPointExtension  ext =(IssuingDistributionPointExtension)crlextensions.get(issuingdpointname);
    return ext;
  }
  
}
