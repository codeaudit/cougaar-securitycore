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
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;

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

    Thread.sleep(timeout);
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
