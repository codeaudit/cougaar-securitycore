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

package test.org.cougaar.core.security.nodetests;

import java.io.*;
import java.util.*;
import java.text.*;
import java.util.regex.*;
import junit.framework.*;
import com.meterware.httpunit.*;

import org.w3c.dom.Document.*;

public class CaWebClient
{
  /** The URL of the CA, e.g. http://cypress:8080
   */
  private String topLevelPageUrl;

  /** The URL to create a CA key, e.g. http://cypress:8080
   */
  private String caCreateKeyUrl;

  /** The URL to list all the agents, e.g. http://cypress:8080/agents?scope=all
   */
  private String agentListUrl;

  /** The URL that points to the index, e.g. http://cypress:8080/$caAgent/CA/Index
   */
  private String caIndexUrl;

  /** The URL that points to the Main window, e.g. http://cypress:8080/$caAgent/CA/Main
   */
  private String caMainUrl;

  /** True if this is the first CA installation (that is, the keystore does
   *  not have a keystore yet).
   */
  private boolean isFirstInstallation;

  public CaWebClient() {
    init();
  }

  public void init() {
    // Initialize parameters
    topLevelPageUrl = System.getProperty("junit.web.topLevelPageUrl");
    Assert.assertNotNull("junit.web.topLevelPageUrl not defined", topLevelPageUrl);

    String s = System.getProperty("junit.web.isFirstInstallation");
    Assert.assertNotNull("junit.web.isFirstInstallation not defined", s);
    isFirstInstallation = Boolean.valueOf(s).booleanValue();

    if (!topLevelPageUrl.endsWith("/")) {
      topLevelPageUrl = topLevelPageUrl + "/";
    }
    caCreateKeyUrl = topLevelPageUrl + "$caAgent/CA/CreateCaKeyServlet";
    agentListUrl = topLevelPageUrl + "agents?scope=all";
    caIndexUrl = topLevelPageUrl + "$caAgent/CA/Index";
    caMainUrl = topLevelPageUrl + "$caAgent/CA/Main";
  }


  public void testCreateCaKey(String arg) {
    // Check top-level page
    String e1[] = {
      "Welcome to Cougaar",
      "<li><a href=\"/agents\">List local agents</a></li>",
      "<li><a href=\"/agents?scope=all\">List all agents</a></li>"
    };
    checkStringsWebResponse(topLevelPageUrl, e1, null);

    // Check agent-list page
    String e2[] = {
      "<li><a href=\"/$caAgent/list\">caAgent</a></li>",
      "<li><a href=\"/$caNode/list\">caNode</a></li>"
    };
    checkStringsWebResponse(agentListUrl, e2, null);

    // Check caIndexUrl page
    String e3[] = {
      "<FRAME name=\"nav\" SRC=\"Browser\">",
      "<FRAME name=\"mainwin\" SRC=\"Main\">"
    };
    checkStringsWebResponse(caIndexUrl, e3, null);

    // Check caMain page
    if (isFirstInstallation) {
      // 
      String e4[] = {
	"<h1>Cougaar Certificate Authority</h1></font>",
	"<h2>Select action in left frame</h2>",
      };
     checkStringsWebResponse(caMainUrl, e4, null);
    }
    else {
     String e5[] = {
	"<h1>Cougaar Certificate Authority</h1></font>",
	"<h2>Select action in left frame</h2>",
	"<br>At list one CA key must be generated before the CA can be used.",
	"<br>Select \"Create CA key\" in the left frame."
     };
     checkStringsWebResponse(caMainUrl, e5, null);
    }

    checkCreateCaForm(caCreateKeyUrl);
  }

  private void checkStringsWebResponse(WebResponse resp,
				       String[] expectedStrings,
				       String[] failureStrings) {
    /* The response may now be manipulated either as pure text (via the toString() method), as a DOM
     * (via the getDOM() method), or by using the various other methods described below. Because
     * the above sequence is so common, it can be abbreviated to:
     */

    String responseHtml = resp.toString();
    // Check that the response contains the strings we expect
    if (expectedStrings != null) {
      for (int i = 0 ; i < expectedStrings.length ; i++) {
	if (responseHtml.indexOf(expectedStrings[i]) == -1) {
	  Assert.fail("Web response does not contain: " + expectedStrings[i]);
	}
      }
    }

    if (failureStrings != null) {
      for (int i = 0 ; i < failureStrings.length ; i++) {
	if (responseHtml.indexOf(failureStrings[i]) != -1) {
	  Assert.fail("Web response contains: " + failureStrings[i]);
	}
      }
    }
  }

  /**
   *  @param url The URL of the web page to check.
   *  @param expectedStrings An array of Strings that the response should contain.
   *  @param failureStrings An array of Strings that the response should NOT contain.
   */
  private void checkStringsWebResponse(String url,
				       String[] expectedStrings,
				       String[] failureStrings) {

    System.out.println("Checking URL: " + url);
    /* The center of HttpUnit is the WebConversation class, which takes the place of a browser talking
     * to a single site. It is responsible for maintaining session context, which it does via cookies
     * returned by the server. To use it, one must create a request and ask the WebConversation for
     * a response.
     */
    WebConversation wc = new WebConversation();
    WebRequest     req = new GetMethodWebRequest(url);
    WebResponse   resp = null;
    try {
      resp = wc.getResponse( req );
    }
    catch (Exception e) {
      Assert.fail("Unable to get response for " + url + " Reason: " + e);
    }
    checkStringsWebResponse(resp, expectedStrings, failureStrings);
  }

  private void checkCreateCaForm(String url) {
    WebConversation wc = new WebConversation();
    WebRequest     req = new GetMethodWebRequest(url);
    WebResponse   resp = null;
    try {
      resp = wc.getResponse( req );
    }
    catch (Exception e) {
      Assert.fail("Unable to get response for " + url + " Reason: " + e);
    }

    // select the first form in the page
    WebForm form = null;
    try {
      form = resp.getForms()[0];
    }
    catch (Exception e) {
      Assert.fail("Unable to get form for " + url + " Reason: " + e);
    }

    WebRequest request = form.getRequest();

    // Set parameters
    request.setParameter( "CN", "JUNIT CA" );
    request.setParameter( "OU", "NAI Labs" );
    request.setParameter( "O", "Network Associates" );
    request.setParameter( "L", "Santa Clara" );
    request.setParameter( "ST", "California" );
    request.setParameter( "C", "USA" );
    request.setParameter( "LDAPurl", "ldap://pear:389/dc=junittest,dc=cougaar,dc=org" );
    request.setParameter( "Validity", "1 y" );
    request.setParameter( "timeEnvelope", "1 h" );
    request.setParameter( "KeySize", "1024" );
    request.setParameter( "RequirePending", "false" );
    request.setParameter( "nodeIsSigner", "true" );

    WebResponse response = null;
    try {
      response = wc.getResponse( request );
    }
    catch (Exception e) {
      Assert.fail("Unable to get response for " + url + " Reason: " + e);
    }
    String e1[] = {
      "<H2>CA key generation</H2>",
      "CA key generation CA key has been generated.<br><br>",
      "CA certificate has been stored in:<br>",
      "CA private key has been stored in:<br>"
    };
    checkStringsWebResponse(response, e1, null);

    /*
    "/home/u/junittest/UL/cougaar/workspace/security/keystores/caNode/keystore-caNode"
    "/home/u/junittest/UL/cougaar/workspace/security/keystores/caNode/keystore-CONUS-RSA"
    */
  }
}

