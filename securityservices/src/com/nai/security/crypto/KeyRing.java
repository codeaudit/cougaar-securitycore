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
 *
 * Created on September 12, 2001, 10:55 AM
 */



package com.nai.security.crypto;



import org.cougaar.util.ConfigFinder;



import java.io.*;

import java.util.Date;

import java.util.HashMap;

import java.util.Hashtable;

import java.util.Enumeration;

import java.util.Vector;

import java.util.Properties;



import java.security.*;

import java.security.cert.*;



/** A common holder for Security keystore information and functionality

 **/



final class KeyRing implements Runnable {

  private static String ksPass;

  private static String ksPath;

  /* added by rakesh tripathi */

  private static String provider_url=null;

  private static CertificateFinder certificatefinder=null;

  private static long sleep_time=2000l; 

  private static KeyStore keystore = null;

  static private boolean debug = false;

  private static HashMap m = new HashMap();


  static {

    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",

						"false"))).booleanValue();

    String installpath = System.getProperty("org.cougaar.install.path");

    String defaultKeystorePath = installpath + File.separatorChar

      + "configs" + File.separatorChar + "common"

      + File.separatorChar + ".keystore";



    ksPass = System.getProperty("org.cougaar.security.keystore.password","alpalp");

    ksPath = System.getProperty("org.cougaar.security.keystore", defaultKeystorePath);

    provider_url = System.getProperty("org.cougaar.security.ldapserver", "ldap://localhost");



    System.out.println("Secure message keystore: path=" + ksPath);

    certificatefinder=new CertificateFinder(provider_url);

  }

  private static void init() {

    try {

      keystore = KeyStore.getInstance(KeyStore.getDefaultType());

      //    InputStream kss = ConfigFinder.getInstance().open(ksPath);

      FileInputStream kss = new FileInputStream(ksPath);

      keystore.load(kss, ksPass.toCharArray());

      

	Enumeration alias = keystore.aliases();

	if (debug) System.out.println("Keystore " + ksPath + " contains:");

	while (alias.hasMoreElements()) {
            try{
                  //build up the hashMap
                  String a = (String)alias.nextElement();
                  X509Certificate x=(X509Certificate)keystore.getCertificate(a);
                  m.put(x.getSubjectDN(), a);
                  if (debug) System.out.println(a);
            }catch(Exception e)
            {
                //e.printStackTrace();
            }
	}

      

      kss.close();

    } catch (Exception e) {

      e.printStackTrace();

    }

  }

  

  private static Object guard = new Object();

  

  public static KeyStore getKeyStore() { 

    synchronized (guard) {

      if (keystore == null) 

        init();

      return keystore; 

    }

  }



  private static HashMap privateKeys = new HashMap(89);

  static PrivateKey getPrivateKey(String name) {

    PrivateKey pk = null;

    try {

      synchronized (privateKeys) {

        pk = (PrivateKey) privateKeys.get(name);

        if (pk == null) {

          pk = (PrivateKey) getKeyStore().getKey(name, ksPass.toCharArray());

	  if (pk == null) {

	    // Try with lower case.

	    pk = (PrivateKey) getKeyStore().getKey(name.toLowerCase(), ksPass.toCharArray());

	    if (pk == null) {

	      // Key was not found in keystore either

	      if (debug) {

		System.out.println("No private key for " + name + " was found in keystore");

	      }

	    }

	  }

	  if (pk != null) {

	      privateKeys.put(name, pk);

	  }

        }

      }

    } catch (Exception e) {

      System.err.println("Failed to get PrivateKey for \""+name+"\": "+e);

      e.printStackTrace();

    }

    return pk;

  }



  private static HashMap certs = new HashMap(89);

  static java.security.cert.Certificate getCert(Principal p) {
      String a = (String) m.get(p);
      return getCert(a);
  }


  static java.security.cert.Certificate getCert(String name) {

    java.security.cert.Certificate cert = null;

    if (debug) {

      System.out.println("CertificateFinder.getCert(" + name + ")");

    }

    CertificateStatus certstatus=null;

    try {

      synchronized (certs) {

	// First, look in local hash map.

        Object o=certs.get(name);

	if(o!=null) {

	  certstatus = (CertificateStatus)o;

	  if(certstatus.isValid())

	    cert=certstatus.getCertificate();

	  if (debug) {

	    System.out.println("CertificateFinder.getCert. Found cert in local hash map:" + name );

	  }

	}

	else {

	  // Look in keystore file.

	  cert = getKeyStore().getCertificate(name);

	  if(cert!=null) {

	    certstatus=new CertificateStatus(cert);

	    certs.put(name, certstatus);

	    if (debug) {

	      System.out.println("CertificateFinder.getCert. Found cert in keystore file:" + name );

	    }

	  }

	  else {

	    // Finally, look in certificate directory service

	    cert=certificatefinder.getCertificate(name);

	    if(cert!=null) {

	      certstatus=new CertificateStatus(cert);

	      certs.put(name,certstatus);
              X509Certificate x = (X509Certificate)cert;
              m.put(x.getSubjectDN(), name);

	      if (debug) {

		System.out.println("CertificateFinder.getCert. Found cert in LDAP:" + name );

	      }

	    }	

	    else {

	      System.err.println("Failed to get Certificate for " + name);

	    }

	  }

	}

      }

    } catch (KeyStoreException e) {

      // Finally, look in certificate directory service

      cert=certificatefinder.getCertificate(name);

      if(cert!=null) {

	certstatus=new CertificateStatus(cert);

	certs.put(name,certstatus);

	if (debug) {

	  System.out.println("CertificateFinder.getCert. Found cert in LDAP:" + name );

	}

      }	

      else {

	System.err.println("Failed to get Certificate for \""+name+"\": "+e);

      }

    }

    return cert;

  }



  /** Lookup Certificate Revocation Lists */

  public void run() {

    while(true) {

      try {

	Thread.sleep(sleep_time);

      }

      catch(InterruptedException interruptedexp) {

	interruptedexp.printStackTrace();

      }

      Hashtable crl=certificatefinder.getCRL();

      Enumeration enum=crl.keys();

      java.security.cert.Certificate certificate=null;

      String alias=null;

      while(enum.hasMoreElements()) {

	alias=(String)enum.nextElement();

	certificate=(java.security.cert.Certificate)crl.get(alias);

	CertificateStatus wrapperobject=new CertificateStatus(certificate, false);

	if (debug) {

	  System.out.println("CertificateFinder.run. Adding CRL for " + alias );

	}

	certs.put(alias,wrapperobject);
        
        //make sure keystore is updated
        try{        getKeyStore().deleteEntry(alias);
                    X509Certificate x = (X509Certificate)certificate;
                    m.remove(x.getSubjectDN());
        }catch(Exception e)
        { e.printStackTrace();}

      }

    }

  }



  public static  void setSleeptime(long sleeptime)

  {

    sleep_time=sleeptime;

  }

  public static long getSleeptime()

  {

    return sleep_time;

  }

  public static Vector getCRL()

  {

    Hashtable crl=certificatefinder.getCRL();

    Enumeration enum=crl.keys();

    String alias=null;

    Vector crllist=new Vector();

    while(enum.hasMoreElements())

      {

	alias=(String)enum.nextElement();

	crllist.addElement(alias);

      }

    return crllist;

  }

}

