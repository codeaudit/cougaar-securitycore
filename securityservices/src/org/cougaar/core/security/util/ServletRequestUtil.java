/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

import java.util.*;
import java.io.*;
import java.security.cert.X509Certificate;

import sun.security.x509.*;
import javax.security.auth.x500.X500Principal;
import java.security.cert.*;
import java.net.*;

public class ServletRequestUtil {

  public InputStream sendRequest(String requestURL, Object req, long timeout)
    throws Exception
  {
    RequestThread t = new RequestThread(requestURL, req);
    t.start();
    if (t.in != null) {
      return t.in;
    }
    if (t.exInfo != null) {
      throw t.exInfo;
    }

    Thread.currentThread().sleep(timeout);
    /*
    t.interrupt();
    if (!t.isInterrupted()) {
      throw new Exception("Fails to interrupt the waiting thread!");
    }
    */

    if (t.in != null) {
      return t.in;
    }
    throw new IOException("Time out waiting for response from " + requestURL);
  }

  class RequestThread extends Thread {
    InputStream in;
    String url;
    Object req;
    Exception exInfo;

    public RequestThread(String requestURL, Object reqObj) {
      url = requestURL;
      req = reqObj;
    }

    public void run() {
      try {
        HttpURLConnection conn = sendRequest(url, req, "POST");
        in = conn.getInputStream();
      }
      catch (Exception ex) {
        exInfo = ex;
      }
    }
  }

  public static HttpURLConnection sendRequest(String requestURL, Object req, String method)
    throws Exception
  {
    URL url = new URL(requestURL);
    HttpURLConnection huc = (HttpURLConnection)url.openConnection();
    // Don't follow redirects automatically.
    huc.setInstanceFollowRedirects(false);
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
    if (req instanceof String) {
      PrintWriter out = new PrintWriter(huc.getOutputStream());
      String content = (String)req;
      out.println(content);
      out.flush();
      out.close();

    }
    else if (req instanceof Serializable) {
      ObjectOutputStream out = new ObjectOutputStream(huc.getOutputStream());
      out.writeObject(req);
      out.flush();
      out.close();
    }
    else {
      throw new Exception("The input object type is not valid.");
    }

    return huc;
  }
}
