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

package com.nai.security.tools;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.input.*;

import java.security.cert.*;
import java.security.KeyStore;
import java.util.*;
import java.io.*;

import com.nai.security.crypto.*;

public class KeyGenerator {

  private static int nbCertificates = 0;
  private static int nbCertificatesSucceed = 0;
  private static String agentName = null;
  private static ConfParser confParser = null;

  public static void main(String args[]) {
    int action = 0;

    if (args.length < 2) {
      System.out.println("Usage: KeyGenerator <xml definition file> options <agent-name>");
      System.out.println("     Where options are one of:");
      System.out.println("          -genkey       : Create key pairs");
      System.out.println("          -gencertsign  : Generate Certificate Signing Requests");
      System.out.println("          -importsigned : Import Certificates signed by CA");
      System.out.println("          -exportpub    : Export public keys from keystore");
      System.out.println("          -importpub    : Import all public keys into each keystore");
      System.out.println("          -removepub    : Remove public keys from keystore");
      System.out.println("                        : Must have called -exportpub before");
      System.out.println("     <agent-name>       : Optional agent name");

      System.out.println(args.length);
      return;
    }
    if (args.length == 3) {
      agentName = args[2];
      System.out.println("Executing for '" + agentName + "' only");
    }
    if (args[1].equals("-genkey")) {
      action = 1;
    } else if (args[1].equals("-gencertsign")) {
      action = 2;
    } else if (args[1].equals("-importsigned")) {
      action = 3;
    } else if (args[1].equals("-exportpub")) {
      action = 4;
    } else if (args[1].equals("-importpub")) {
      action = 5;
    } else if (args[1].equals("-removepub")) {
      action = 6;
    }
    System.setProperty("org.cougaar.security.crypto.config", args[0]);

    confParser = new ConfParser();

    Element root = confParser.getConfigDocument().getRootElement();
    iterateKeyStore(root, action);

    System.out.println("Total number of certificates:        " + nbCertificates);
    System.out.println("Certificates successfully processed: " + nbCertificatesSucceed);
  }


  public static void iterateKeyStore(Element element, int action) {
    
    List societyChildren = element.getContent();
    Iterator keyStoreIterator = societyChildren.iterator();
    // Iterate through each key store
    while (keyStoreIterator.hasNext()) {
      Object o = keyStoreIterator.next();
      if (o instanceof Element
	  && ((Element)o).getName().equals("keystorefile")) {
	Element keyNode = (Element)o;
	String keyStoreName =  keyNode.getChildText("keystore");
	String keyStorePasswd = keyNode.getChildText("storepass");
		
	System.out.println("keystore: " + keyStoreName);

	List keyStoreChildren = keyNode.getContent();
	Iterator keyIterator = keyStoreChildren.iterator();

	// Iterate through keys
	while (keyIterator.hasNext()) {
	  Object keyo = keyIterator.next();
	  if (keyo instanceof Element) {
	    if (((Element)keyo).getName().equals("key")) {
	      if (agentName != null) {
		String alias = ((Element)keyo).getChildText("alias");
		if (alias.equals(agentName) == false) {
		  System.out.println("Skipping " + alias + "...");
		  continue;
		}
	      }
	      switch (action) {
	      case 1: // Generate keys
		createKeyPairWithKeyTool((Element)keyo, keyStoreName, keyStorePasswd);
		break;
	      case 2: // Create Certificate Signing Requests
		createCertificateRequestWithKeyTool((Element)keyo, keyStoreName, keyStorePasswd);
		break;
	      case 3: // Import Signed Certificates
		importSigneCertificateWithKeyTool((Element)keyo, keyStoreName, keyStorePasswd);
		break;
	      case 4: // Export public key Certificates
		exportCertificatesWithKeyTool((Element)keyo, keyStoreName, keyStorePasswd);
		break;
	      case 5: // Import public key Certificates
		importCertificatesWithKeyTool((Element)keyo, keyStoreName, keyStorePasswd);
		break;
	      case 6: // Remove public keys from Certificates
		removeCertificatesWithKeyTool((Element)keyo, keyStoreName, keyStorePasswd);
		break;
	      default:
		break;
	      }
	    }

	    if (((Element)keyo).getName().equals("trustedCA")) {
	      switch (action) {
	      case 3: // Import trusted authority
		importTrustedAuthorityWithKeyTool((Element)keyo, keyStoreName, keyStorePasswd);
		break;
	      default:
		break;
	      }
	    }
	  }
	}
      }
    }
  }

  public static KeyStore loadKeyStore(String keyStoreName,
				      String keyStorePasswd) {
    KeyStore keyStore = null;
    InputStream in = null;
    try {
      in = new FileInputStream(keyStoreName);

      keyStore = KeyStore.getInstance(keyStore.getDefaultType());
      keyStore.load(in, keyStorePasswd.toCharArray());
    } catch(java.io.FileNotFoundException e) {
      e.printStackTrace();
    } catch(java.security.KeyStoreException e) {
      e.printStackTrace();
    } catch(java.security.NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch(java.security.cert.CertificateException e) {    
      e.printStackTrace();
    } catch(java.io.IOException e) {
      e.printStackTrace();
    }
    return keyStore;
  }

  public static void storeKeyStore(KeyStore keyStore,
				   String keyStoreName,
				   String keyStorePasswd) {
    try {
      OutputStream out = new FileOutputStream(keyStoreName);
      keyStore.store(out, keyStorePasswd.toCharArray());
    } catch(java.io.IOException e) {
      e.printStackTrace();
    } catch(java.security.KeyStoreException e) {
      e.printStackTrace();
    } catch(java.security.NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch(java.security.cert.CertificateException e) {    
      e.printStackTrace();
    }
  }

  public static void iterateKey(Element element,
				String keyStoreName,
				String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String keypass = element.getChildText("keypass");
    String keyalg = element.getChildText("keyalg");
    String sigalg = element.getChildText("sigalg");
    String keysize = element.getChildText("keysize");
    String dname = element.getChildText("dname");

  }

  public static void createKeyPairWithKeyTool(Element element,
					      String keyStoreName,
					      String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String keypass = element.getChildText("keypass");
    String keyalg = element.getChildText("keyalg");
    String sigalg = element.getChildText("sigalg");
    String keysize = element.getChildText("keysize");
    String dname = element.getChildText("dname");

    List genKeyCom = new ArrayList();

    genKeyCom.add("keytool");
    genKeyCom.add("-genkey");
    if (keyStorePasswd != null) {
      genKeyCom.add("-storepass");
      genKeyCom.add(keyStorePasswd);
    }
    if (keyStoreName != null) {
      genKeyCom.add("-keystore");
      genKeyCom.add("KeyStores/" + keyStoreName);
    }
    if (alias != null) {
      genKeyCom.add("-alias");
      genKeyCom.add(alias);
    }
    if (keypass != null) {
      genKeyCom.add("-keypass");
      genKeyCom.add(keypass);
    }
    if (keyalg != null) {
      genKeyCom.add("-keyalg");
      genKeyCom.add(keyalg);
    }
    if (sigalg != null) {
      genKeyCom.add("-sigalg");
      genKeyCom.add(sigalg);
    }
    if (keysize != null) {
      genKeyCom.add("-keysize");
      genKeyCom.add(keysize);
    }
    if (dname != null) {
      genKeyCom.add("-dname");
      genKeyCom.add(dname);
    }
    System.out.println("Creating key for " + alias);
    executeCommand(genKeyCom);
  }

  public static void executeCommand(List commandLine) {
    try {
      String[] command = new String[commandLine.size()];
      for (int i = 0 ; i < commandLine.size() ; i++) {
	command[i] = (String) commandLine.get(i);
      }

      nbCertificates++;

      Runtime rt = Runtime.getRuntime();
      Process process = rt.exec(command);

      BufferedReader in = new BufferedReader(
					     new InputStreamReader(process.getInputStream()));
      BufferedReader err = new BufferedReader(
					      new InputStreamReader(process.getErrorStream()));
   
      boolean isError = false;
      String line = null;

      while ((line = err.readLine()) != null) {
	System.out.println("keytool stderr:" + line);
	isError = true;
      }
      while ((line = in.readLine()) != null) {
	System.out.println("keytool stdout:" + line);
	isError = true;
      }
      process.waitFor();
      if ((process.exitValue() == 0) && (isError == false)) {
	nbCertificatesSucceed++;
      }

    } catch(java.io.IOException e) {
      e.printStackTrace();
    } catch(java.lang.InterruptedException e) {
      e.printStackTrace();
    }
  }

  public static void createCertificateRequestWithKeyTool(Element element,
							 String keyStoreName,
							 String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String keypass = element.getChildText("keypass");
    String dname = element.getChildText("dname");
    String signingAuthority = element.getChildText("signingAuthority");

    List genKeyCom = new ArrayList();

    genKeyCom.add("keytool");
    genKeyCom.add("-certreq");
    if (keyStorePasswd != null) {
      genKeyCom.add("-storepass");
      genKeyCom.add(keyStorePasswd);
    }
    if (keyStoreName != null) {
      genKeyCom.add("-keystore");
      genKeyCom.add("KeyStores/" + keyStoreName);
    }

    if (alias != null) {
      genKeyCom.add("-alias");
      genKeyCom.add(alias);
    }
    if (keypass != null) {
      genKeyCom.add("-keypass");
      genKeyCom.add(keypass);
    }
    genKeyCom.add("-file");
    genKeyCom.add("CertificateSigningRequests/certSignReq-" + signingAuthority + "-" + alias + ".cer");

    System.out.println("Creating signing certificate request for " + alias);
    executeCommand(genKeyCom);
  }

  public static void importSigneCertificateWithKeyTool(Element element,
						       String keyStoreName,
						       String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String keypass = element.getChildText("keypass");
    String signingAuthority = element.getChildText("signingAuthority");

    List genKeyCom = new ArrayList();

    genKeyCom.add("keytool");
    genKeyCom.add("-import");
    if (keyStorePasswd != null) {
      genKeyCom.add("-storepass");
      genKeyCom.add(keyStorePasswd);
    }
    if (keyStoreName != null) {
      genKeyCom.add("-keystore");
      genKeyCom.add("KeyStores/" + keyStoreName);
    }

    if (alias != null) {
      genKeyCom.add("-alias");
      genKeyCom.add(alias);
    }
    if (keypass != null) {
      genKeyCom.add("-keypass");
      genKeyCom.add(keypass);
    }

    genKeyCom.add("-file");
    genKeyCom.add("CaSignedCertificates/SignedReq-" + signingAuthority + "-" + alias + ".cer");

    System.out.println("Importing Signed Certificate for " + alias);
    executeCommand(genKeyCom);
  }

  public static void importTrustedAuthorityWithKeyTool(Element element,
						       String keyStoreName,
						       String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String fileName = element.getChildText("file");

    List genKeyCom = new ArrayList();

    genKeyCom.add("keytool");
    genKeyCom.add("-import");
    genKeyCom.add("-noprompt");
    if (keyStorePasswd != null) {
      genKeyCom.add("-storepass");
      genKeyCom.add(keyStorePasswd);
    }
    if (keyStoreName != null) {
      genKeyCom.add("-keystore");
      genKeyCom.add("KeyStores/" + keyStoreName);
    }
    genKeyCom.add("-trustcacerts");

    if (alias != null) {
      genKeyCom.add("-alias");
      genKeyCom.add(alias);
    }
    else {
      System.out.println("Error: alias missing");
      return;
    }
    if (fileName != null) {
      genKeyCom.add("-file");
      genKeyCom.add("CaCertificates/" + fileName);
    }
    else {
      System.out.println("Error: file name missing");
      return;
    }

    System.out.println("Importing trusted CA: " + alias);
    executeCommand(genKeyCom);
  }

  public static void exportCertificatesWithKeyTool(Element element,
						   String keyStoreName,
						   String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String signingAuthority = element.getChildText("signingAuthority");

    List genKeyCom = new ArrayList();

    genKeyCom.add("keytool");
    genKeyCom.add("-export");
    genKeyCom.add("-rfc");

    if (keyStorePasswd != null) {
      genKeyCom.add("-storepass");
      genKeyCom.add(keyStorePasswd);
    }
    if (keyStoreName != null) {
      genKeyCom.add("-keystore");
      genKeyCom.add("KeyStores/" + keyStoreName);
    }

    if (alias != null) {
      genKeyCom.add("-alias");
      genKeyCom.add(alias);
    }
    else {
      System.out.println("Error: alias missing");
      return;
    }
    genKeyCom.add("-file");
    genKeyCom.add("PublicKeys/pubKeyCert-" + signingAuthority + "-" + alias + ".cer");

    System.out.println("Exporting public key certificates: " + alias);
    executeCommand(genKeyCom);
  }

  public static void importCertificatesWithKeyTool(Element element,
						   String keyStoreName,
						   String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String signingAuthority = element.getChildText("signingAuthority");


    // Iterate through all parents (keystores) and store public key in all keystores
    // Except for the current key store, since the key is already there.

    List keyStore = element.getParent().getParent().getContent();
    Iterator keyStoreIterator = keyStore.iterator();

    while (keyStoreIterator.hasNext()) {
      Object o = keyStoreIterator.next();
      if (o instanceof Element
	  && ((Element)o).getName().equals("keystorefile")) {
	Element keyNode = (Element)o;
	String otherKeyStoreName =  keyNode.getChildText("keystore");
	String otherKeyStorePasswd = keyNode.getChildText("storepass");
	if (keyStoreName.equals(otherKeyStoreName)) {
	  // Skipping
	  System.out.println("Skipping " + otherKeyStoreName);
	  continue;
	}

	List genKeyCom = new ArrayList();
		    
	genKeyCom.add("keytool");
	genKeyCom.add("-import");
	genKeyCom.add("-noprompt");
		
	if (keyStorePasswd != null) {
	  genKeyCom.add("-storepass");
	  genKeyCom.add(otherKeyStorePasswd);
	}
	if (keyStoreName != null) {
	  genKeyCom.add("-keystore");
	  genKeyCom.add("KeyStores/" + otherKeyStoreName);
	}
		
	if (alias != null) {
	  genKeyCom.add("-alias");
	  genKeyCom.add(alias);
	}
	else {
	  System.out.println("Error: alias missing");
	  return;
	}
	genKeyCom.add("-file");
	genKeyCom.add("PublicKeys/pubKeyCert-" + signingAuthority + "-" + alias + ".cer");
		
	System.out.println("   Importing public key certificates: " + alias
			   + " into " + otherKeyStoreName);
	executeCommand(genKeyCom);
      }
    }
  }

  public static void removeCertificatesWithKeyTool(Element element,
						   String keyStoreName,
						   String keyStorePasswd) {
    String alias = element.getChildText("alias");
    String signingAuthority = element.getChildText("signingAuthority");

    List genKeyCom = new ArrayList();

    genKeyCom.add("keytool");
    genKeyCom.add("-delete");

    if (keyStorePasswd != null) {
      genKeyCom.add("-storepass");
      genKeyCom.add(keyStorePasswd);
    }
    if (keyStoreName != null) {
      genKeyCom.add("-keystore");
      genKeyCom.add("KeyStores/" + keyStoreName);
    }

    if (alias != null) {
      genKeyCom.add("-alias");
      genKeyCom.add(alias);
    }
    else {
      System.out.println("Error: alias missing");
      return;
    }
    genKeyCom.add("-file");
    genKeyCom.add("PublicKeys/pubKeyCert-" + signingAuthority + "-" + alias + ".cer");

    System.out.println("Exporting public key certificates: " + alias);
    executeCommand(genKeyCom);
  }
}
