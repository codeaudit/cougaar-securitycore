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

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.cert.X509Certificate;
import sun.security.x509.*;
import java.security.cert.*;
import java.security.PublicKey;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import com.nai.security.policy.CaPolicy;
import com.nai.security.crypto.CertificateUtility;
import org.cougaar.core.security.services.util.*;
import  org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.provider.SecurityServiceProvider;

public class PendingCertCache
  extends Hashtable
{
  private SecurityPropertiesService secprop = null;

  private CaPolicy caPolicy = null;            // the policy of the CA
  private String x509DirectoryName = null;
  protected boolean debug = false;

  private static PendingCertCache thisCache = null;
  private CertificateManagementService signer = null;
  private ServiceBroker serviceBroker;
  private ConfigParserService configParser = null;

  // singleton
  // only started once
  public synchronized static PendingCertCache getPendingCache(
    String cadnname, String role, String certpath,
    ServiceBroker sb) {
    if (thisCache == null) {
      try {
        thisCache = new PendingCertCache(cadnname, role,
					 certpath, sb);
      }
      catch (Exception e) {
        System.out.println("Error creating PendingCertCache: " + e.toString());
      }
    }
    return thisCache;
  }

  private PendingCertCache(String cadnname, String role,
			   String certpath,
			   ServiceBroker sb) 
    throws Exception {
    serviceBroker = sb;
    configParser = (ConfigParserService)
      serviceBroker.getService(this,
			       ConfigParserService.class,
			       null); 
    try {
      caPolicy = configParser.getCaPolicy(cadnname);

      signer = (CertificateManagementService)
	serviceBroker.getService(this,
				 CertificateManagementService.class,
				 null);
      signer.setParameters(cadnname);
    }
    catch (Exception e) {
      throw new Exception("Unable to read policy for DN="
			  + cadnname + ". Role="
                          + role + " - " + e );
    }
    init();
  }

  public synchronized static PendingCertCache getPendingCache(
    CaPolicy aCaPolicy,
    CertificateManagementService aSigner) {
    if (thisCache == null) {
      try {
        thisCache = new PendingCertCache(aCaPolicy, aSigner);
      }
      catch (Exception e) {
        System.out.println("Error creating PendingCertCache: " + e.toString());
        e.printStackTrace();
      }
    }
    return thisCache;
  }

  private PendingCertCache (CaPolicy aCaPolicy,
			    CertificateManagementService aSigner) 
    throws Exception {
    caPolicy = aCaPolicy;
    signer = aSigner;
    init();
  }

  private void init()
    throws Exception {
    secprop = SecurityServiceProvider.getSecurityProperties(null);
    debug = (Boolean.valueOf(secprop.getProperty(secprop.CRYPTO_DEBUG,
						"false"))).booleanValue();

    x509DirectoryName = signer.getX509DirectoryName();
    loadRequests();
  }


  private synchronized void loadRequests()
    throws Exception {
    // there are 3 directories storing certificates which should be loaded
    // 1. the pending request, which will be used when viewing and approving requests
    put(caPolicy.pendingDirectory,
      loadCertCache(x509DirectoryName + File.separatorChar +
        caPolicy.pendingDirectory + File.separatorChar));
    // 2. the valid certificate, which will be used when need to reply client with
    //  a certificate approved
    put(caPolicy.x509CertDirectory, loadCertCache(x509DirectoryName + File.separatorChar));
    // 3. the denied request, which will be checked when client send a query request
    //  to check whether the request has been processed
    put(caPolicy.deniedDirectory,
      loadCertCache(x509DirectoryName + File.separatorChar +
        caPolicy.deniedDirectory + File.separatorChar));
  }

  private Hashtable loadCertCache(String certsubdir) {
    Hashtable certtable = new Hashtable();
    ArrayList filelist = getCertFileList(certsubdir);
    for (int i = 0; i < filelist.size(); i++) {
      ArrayList certs = getCertFromFileList(certsubdir, (String)filelist.get(i));
      for (int j = 0; j < certs.size(); j++)
        certtable.put(filelist.get(i), certs.get(j));
    }
    return certtable;
  }

  public Certificate getCertificate(String whichstate, String alias) {
    Hashtable certtable = (Hashtable)get(whichstate);
    if (certtable == null)
      return null;
    return (Certificate)certtable.get(alias);
  }

  // using public key as key
  public Certificate getCertificate(String whichstate, PublicKey publicKey) {
    Hashtable certtable = (Hashtable)get(whichstate);
    if (certtable == null)
      return null;

    String pubkeyValue = new String(publicKey.getEncoded());
    if (debug) {
      System.out.println("getting cert with pub key: ");
    }

    for (Enumeration en = certtable.elements(); en.hasMoreElements(); ) {
      Certificate certimpl = (Certificate)en.nextElement();
      if (pubkeyValue.equals(new String(certimpl.getPublicKey().getEncoded())))
        return certimpl;
    }
    return null;
  }

  public static void addCertificateToList(String whichstate, String alias, Certificate cert) {
    // NOTE: if the cache is not loaded yet, no need to put the cert in cache
    // the time that the cache is loaded the new cert will be loaded
    // this operation is to keep the cache in sych in case the cache exists
    if (thisCache != null) {
      Hashtable certtable = (Hashtable)thisCache.get(whichstate);
      if (certtable != null)
        certtable.put(alias, cert);
    }
  }

  public void moveCertificate(String fromstate, String tostate, String alias) {
    Certificate certimpl = getCertificate(fromstate, alias);
    if (certimpl != null) {
      addCertificateToList(tostate, alias, certimpl);

      Hashtable certtable = (Hashtable)thisCache.get(fromstate);
      if (certtable != null)
        certtable.remove(alias);

      String topath = x509DirectoryName + File.separatorChar;
      // from is always pending, so just add it
      String frompath = topath + fromstate + File.separatorChar + alias + ".cer";
      if (!tostate.equals(caPolicy.x509CertDirectory))
        topath += tostate + File.separatorChar;
      topath += alias + ".cer";
      File fromfile = new File(frompath);
      if (fromfile.exists())
        fromfile.renameTo(new File(topath));
      if (debug) {
        System.out.println("moving file: " + fromfile + " to: " + topath);
      }
    }
  }

  // Richard - get list of certificate request from the files saved
  public ArrayList getCertFileList(String certdir) {
    ArrayList ar = new ArrayList();
    File f = new File(certdir);
    if (f.exists()) {
      File [] certfiles = f.listFiles();
      for (int i = 0; i < certfiles.length; i++) {
        File certfile = certfiles[i];
        String filename = certfile.getName();
        int separatorIndex = filename.lastIndexOf(".cer");
        if (separatorIndex > 0) {
          // extract the alias from filename
          ar.add(filename.substring(0, separatorIndex));
        }

      }
    }
    return ar;
  }

  public ArrayList getCertFromFileList(String certsubdir, String alias) {
    ArrayList certlist = new ArrayList();
    File certfile = new File(certsubdir + File.separatorChar + alias + ".cer");
    try {
      //X509CertImpl ClientX509 = new X509CertImpl(new FileInputStream(certfile));
      certlist = signer.readX509Certificates(certfile.getPath());
    }
    catch(CertificateException certificateexception) {
    }
    catch(IOException ioexception1) {
    }
    catch(Exception e) {
      System.out.println("Exception when loading certificate from file: " + certfile.getPath());
      e.printStackTrace();
    }
    return certlist;
  }

}
