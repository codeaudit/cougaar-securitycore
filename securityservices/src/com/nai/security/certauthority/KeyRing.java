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

package com.nai.security.certauthority;
													
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

final class KeyRing {

  private static String ksPass;
  private static String ksPath;
  private static String provider_url=null;

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

	System.out.println("Secure message keystore: path=" + ksPath);
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
  private static HashMap privateKeys = new HashMap(89);

	  

  public static KeyStore getKeyStore() { 
			if (keystore == null) 
        init();
      return keystore; 
		}


  public static PrivateKey getPrivateKey(String name) {
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

}


