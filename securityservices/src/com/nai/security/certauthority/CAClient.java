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
 * Created on November 7, 2001, 4:42 PM
 */

package com.nai.security.certauthority;

import java.security.*;
import java.security.cert.*;
import java.net.*;
import java.io.*;
//import java.net.HttpURLConnection.*;

import com.nai.security.policy.NodePolicy;
import com.nai.security.crypto.ConfParser;

public class CAClient {

  private KeyPairGenerator kpg;
  private NodePolicy policy;
  private boolean debug = false;
  private String role = null;

  /** Creates new CertGenerator */
  public CAClient(String aRole) {
    debug = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.crypto.debug",
						"false"))).booleanValue();

    role = aRole;

    ConfParser confParser = new ConfParser();
    try{
      //kpg = KeyPairGenerator.getInstance("RSA");
            
      //get related policies 
      policy = confParser.readNodePolicy(role);
            
    } catch(Exception e) {
      System.out.println("Error: can't start CA client--"+e.getMessage());
      e.printStackTrace();
    }
  }

  public NodePolicy getNodePolicy() {
    return policy;
  }

  public String sendPKCS(String request, String pkcs){
    String reply = "";
    try {
      if (debug) {
	System.out.println("Sending request to " + policy.CA_URL
			   + ", DN= " + policy.CA_DN);
	System.out.println(request);
	System.out.println("DN= " + policy.CA_DN);
      }
      URL url = new URL(policy.CA_URL);
      HttpURLConnection huc = (HttpURLConnection)url.openConnection();
      // Let the system know that we want to do output
      huc.setDoOutput(true);
      // Let the system know that we want to do input
      huc.setDoInput(true);
      // No caching, we want the real thing
      huc.setUseCaches(false);
      // Specify the content type
      huc.setRequestProperty("Content-Type",
			     "application/x-www-form-urlencoded");
      huc.setRequestMethod("POST");
      PrintWriter out = new PrintWriter(huc.getOutputStream());
      String content = "pkcs=" + URLEncoder.encode(pkcs);
      content = content + "&role=" + URLEncoder.encode(role);
      content = content + "&dnname=" + URLEncoder.encode(policy.CA_DN);
      content = content + "&pkcsdata=" + URLEncoder.encode(request);
      out.println(content);
      out.flush();
      out.close();

      BufferedReader in = new BufferedReader(new InputStreamReader(huc.getInputStream()));
      int len = 2000;     // Size of a read operation
      char [] cbuf = new char[len];
      while (in.ready()) {
	int read = in.read(cbuf, 0, len);
	reply = reply + new String(cbuf, 0, read);
      }
      in.close();
      if (debug) {
	System.out.println("Reply: " + reply);
      }
 
    } catch(Exception e) {
      System.err.println("Error: sending PKCS request to CA failed--"
			 + e.getMessage());
      e.printStackTrace();
    }
    return reply;
  }
        
  public String signPKCS(String request, String nodeDN){
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try{
      if (debug) {
	System.out.println("Signing PKCS10 request with node");
      }
      KeyManagement km = new KeyManagement(nodeDN, null);
      X509Certificate[] cf = km.processPkcs10Request(new ByteArrayInputStream(request.getBytes()));
      PrintStream ps = new PrintStream(baos);
      km.base64EncodeCertificates(ps, cf);
      //get the output to the CA
      String req = baos.toString();
      String reply = sendPKCS(req, "PKCS7");
    }catch(Exception e){
      System.err.println("Error: can't get the certificate signed--"
			 + e.getMessage());
      e.printStackTrace();
    }    
    return baos.toString();
  }

}
