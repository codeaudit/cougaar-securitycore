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

package org.cougaar.core.security.util;

import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import org.cougaar.core.security.crlextension.x509.extensions.CertificateIssuerExtension;
import org.cougaar.core.security.crlextension.x509.extensions.CougaarGeneralNames;
import org.cougaar.core.security.crlextension.x509.extensions.IssuingDistributionPointExtension;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.CRLExtensions;
import sun.security.x509.Extension;
import sun.security.x509.GeneralName;
import sun.security.x509.OIDMap;
import sun.security.x509.X500Name;
import sun.security.x509.X509AttributeName;
import sun.security.x509.X509CRLEntryImpl;
import sun.security.x509.X509CRLImpl;

public class CrlUtility {
  public static final String issuingdpointname="IssuingDistibutionPoint";
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger(CrlUtility.class);
  }

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
    //X509CRLEntry [] crlentry=new X509CRLEntry[1];
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
      while (i.hasNext()) {
	crlentry=(X509CRLEntry)i.next();
	crlentrys.add(crlentry);
      }
    }
    crlentrys.trimToSize();
     
    X509CRLImpl crlimpl=null;
    X509CRLEntry[] crlentryarray=new X509CRLEntry[crlentrys.size()+1];
    crlentrys.copyInto(crlentryarray);
    
    PublicKey issuerPublicKey=clientIssuerCert.getPublicKey();
    //String userDN=clientCert.getSubjectDN().getName();
    CRLExtensions  extensions=null;
    X509CRLEntryImpl crlentryimpl=null;
    try {
      extensions= getExtensions(caCRL);
    }
    catch ( IOException ioexp) {
      if (_log.isWarnEnabled()) {
	_log.warn("Unable to get Certificate extensions", ioexp);
      }
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
      // Encode X500Name
      DerOutputStream deroutputstream = new DerOutputStream();
      username.encode(deroutputstream);
      DerValue derValue = new DerValue(deroutputstream.toByteArray());
      CougaarGeneralNames gns = new CougaarGeneralNames();
      GeneralName gn = new GeneralName(derValue);
      if (_log.isDebugEnabled()) {
	_log.debug("General Name type: " + gn.getType());
      }
      gns.add(gn);
      //CertificateIssuerExtension cie=new CertificateIssuerExtension();
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
