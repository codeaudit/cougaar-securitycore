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
  /** The URL of the CA, e.g. http://cypress:8080 */
  private String topLevelPageUrl;

  /** The URL to create a CA key, e.g. http://cypress:8080  */
  private String caCreateKeyUrl;

  /** The URL to list all the agents, e.g. http://cypress:8080/agents?scope=all  */
  private String agentListUrl;

  /** The URL that points to the index, e.g. http://cypress:8080/$caAgent/CA/Index  */
  private String caIndexUrl;

  /** The URL that points to the Main window, e.g. http://cypress:8080/$caAgent/CA/Main.  */
  private String caMainUrl;

  /** The URL that points to the certificate list window, e.g. http://cypress:8080/$caAgent/CA/CertificateList.  */
  private String caListUrl;

  /** The URL that points to the CA keys window, e.g. http://cypress:8080/$caAgent/CA/ListCaKeysServlet.  */
  private String caListCaUrl;

  /** True if this is the first CA installation (that is, the keystore does
   *  not have a keystore yet).
   */
  private boolean isFirstInstallation;


  private String cnValue = "JUNIT CA";
  private String ouValue = "NAI Labs";
  private String oValue = "Network Associates";
  private String lValue = "Santa Clara";
  private String stValue = "California";
  private String cValue = "USA";
  private String lDAPurlValue = "ldap://pear:389/dc=junittest,dc=cougaar,dc=org";
  private String validityValue = "1 y";
  private String timeEnvelopeValue = "1 h";
  private String keySizeValue = "1024";
  private String requirePendingValue = "false";
  private String nodeIsSignerValue = "true";

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
    caListUrl = topLevelPageUrl + "$caAgent/CertificateList";
    caListCaUrl = topLevelPageUrl + "$caAgent/CA/ListCaKeysServlet";
  }

  public static void main(String args[]) {
    CaWebClient client = new CaWebClient();
    client.testCreateCaKey("foo");
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
    String e4[] = {
      "<h1>Cougaar Certificate Authority</h1></font>",
      "<h2>Select action in left frame</h2>",
      };
    String e44[] = {
      "<br>At list one CA key must be generated before the CA can be used.",
      "<br>Select \"Create CA key\" in the left frame."
    };
    String e5[] = {
      "<h1>Cougaar Certificate Authority</h1></font>",
      "<h2>Select action in left frame</h2>",
      "<br>At list one CA key must be generated before the CA can be used.",
      "<br>Select \"Create CA key\" in the left frame."
     };

    if (isFirstInstallation) {
      checkStringsWebResponse(caMainUrl, e5, null);
    }
    else {
      checkStringsWebResponse(caMainUrl, e4, e44);
    }

    checkCreateCaForm(caCreateKeyUrl);

    // Check caListCaUrl page
    // The first time the CA is started, it does not have agent and node keys yet.
    String e6[] = {
      "<title>CA Keys List</title>",
      "<TR><TH> DN-Certificate </TH><TH> DN-Signed By </TH></TR>",
      "TD>CN=" + cnValue + ", OU=" + ouValue + ", O=" + oValue + ", L=" + lValue
        + ", ST=" + stValue + ", C=" + cValue + ", T=ca</TD>"
    };

    // The second time the CA is started, it should have the agent and node keys.
    String e7[] = {
      "<title>CA Keys List</title>",
      "<TR><TH> DN-Certificate </TH><TH> DN-Signed By </TH></TR>",
      "TD>CN=" + cnValue + ", OU=" + ouValue + ", O=" + oValue + ", L=" + lValue
      + ", ST=" + stValue + ", C=" + cValue + ", T=ca</TD>",
      "<TD>CN=caAgent, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US, T=agent</TD>",
      "<TD>CN=caNode, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US, T=node</TD>"
    };
    if (isFirstInstallation) {
      checkStringsWebResponse(caListCaUrl, e6, null);
    }
    else {
      checkStringsWebResponse(caListCaUrl, e7, null);
    }

  }

  private void checkStringsWebResponse(WebResponse resp,
				       String[] expectedStrings,
				       String[] failureStrings) {
    /* The response may now be manipulated either as pure text (via the toString() method), as a DOM
     * (via the getDOM() method), or by using the various other methods described below. Because
     * the above sequence is so common, it can be abbreviated to:
     */

    try {
      String responseHtml = resp.getText();
      // Check that the response contains the strings we expect
      if (expectedStrings != null) {
	for (int i = 0 ; i < expectedStrings.length ; i++) {
	  if (responseHtml.indexOf(expectedStrings[i]) == -1) {
	    System.err.println("Error: Unexpected page content:\n" + resp.getText());
	    Assert.fail("Web response does not contain: " + expectedStrings[i]);
	  }
	}
      }

      if (failureStrings != null) {
	for (int i = 0 ; i < failureStrings.length ; i++) {
	  if (responseHtml.indexOf(failureStrings[i]) != -1) {
	    System.err.println("Error: Unexpected page content:\n" + resp.getText());
	    Assert.fail("Web response contains: " + failureStrings[i]);
	  }
	}
      }
    } catch (Exception e) {
      Assert.fail("Unable to get Web Response: " + e);
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
    System.out.println("Checking URL: " + url + ": OK");
  }

  private void checkCreateCaForm(String url) {
    WebConversation wc = new WebConversation();
    WebRequest     req = new GetMethodWebRequest(url);
    WebResponse   resp = null;

    try {
      // User authentication is required, so this should throw an exception.
      resp = wc.getResponse( req );
    }
    catch (AuthorizationRequiredException e) {
      System.out.println("Authentication is required: " + e.getAuthenticationScheme());
      // Try again with appropriate credentials
      String userName = System.getProperty("junit.ca.user.name");
      Assert.assertNotNull("junit.ca.user.name property should be set", userName);
      String password = System.getProperty("junit.ca.user.password");
      Assert.assertNotNull("junit.ca.user.password property should be set", password);

      wc.setAuthorization(userName, password);
      try {
	resp = wc.getResponse(req);
	System.out.println("Authentication succeeded.");
      }
      catch (Exception e1) {
	Assert.fail("Unable to get response for " + url + " Reason: " + e1);
      }
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
    request.setParameter( "CN", cnValue );
    request.setParameter( "OU", ouValue );
    request.setParameter( "O", oValue );
    request.setParameter( "L", lValue );
    request.setParameter( "ST", stValue );
    request.setParameter( "C", cValue );
    request.setParameter( "LDAPurl", lDAPurlValue );
    request.setParameter( "Validity", validityValue );
    request.setParameter( "timeEnvelope", timeEnvelopeValue );
    request.setParameter( "KeySize", keySizeValue );
    request.setParameter( "RequirePending", requirePendingValue );
    request.setParameter( "nodeIsSigner", nodeIsSignerValue );

    WebResponse response = null;
    try {
      response = wc.getResponse( request );
    }
    catch (Exception e) {
      Assert.fail("Unable to get response for " + url + " Reason: " + e);
    }
    String e1[] = {
      "<H2>CA key generation</H2>",
      "CA key generation",
      "CA key has been generated.<br><br>",
      "CA certificate has been stored in:<br>",
      "CA private key has been stored in:<br>"
    };
    checkStringsWebResponse(response, e1, null);

    /*
    "/home/u/junittest/UL/cougaar/workspace/security/keystores/caNode/keystore-caNode"
    "/home/u/junittest/UL/cougaar/workspace/security/keystores/caNode/keystore-CONUS-RSA"
    */
  }

  /**
   *  I-CBTSVCSUP-NODE            10 agents'
   *          24-SPTGP-HHC
   *          24-CSB-HHD
   *          110-QMCO-POLSPLY
   *          553-CSB-HHD
   *          10-TCBN-HHC
   *          416-TKCO-POL
   *          89-TKCO-CGO
   *          180-TCBN-HHD
   *          418-TKCO-POL
   *          92-ENGBN-CBTHVY
   *  I-COMMAND-NODE               3 agents'
   *          NCA
   *          CENTCOM-HHC
   *          JTF-HHC
   *  I-CONUS-DIV-NODE             5 agents'
   *          3ID-HHC'
   *          3-DISCOM-HHC
   *          703-MSB
   *          DLAHQ
   *          IOC
   *  I-IBCT-2BDE-NODE             7 agents'
   *          2-7-INFBN
   *          2-BDE-3ID-HHC
   *          3-69-ARBN
   *          3-FSB
   *          3-BDE-2ID-HHC
   *          1-23-INFBN
   *          296-SPTBN
   *  I-TRANSCOM-NODE              1 agent'
   *          TRANSCOM 
   *  TEST-NODE-NCADomainManager   1 agent
   *          NCADomainManager
   *                              ---------
   *                              27 agents       27 certificates
   *  6 nodes                                     33 certificates
   *  6 hosts                                     39 certificates
   * 
   *  CA-NODE: agent + node + host + ca           43 certificates
   *          caAgent'
   *          caNode'
   *          Junit CA'
   *
   */

  public void checkCertificateList(String expectedCertificates) {
    String e1[] = {
      "<title>Certificate List from Ldap </title>",
      "<H2>Certificate List</H2>",
      "Select CA: <select id=\"cadnname\" name=\"cadnname\">",
      "<option value=\"CN=" + cnValue + ", OU=" + ouValue + ", O=" + oValue
      + ", L=" + lValue + ", ST=" + stValue + ", C=" + cValue
      + ", T=ca\">",
    };
    checkStringsWebResponse(caListUrl, e1, null);

    // What is the number of expected certificates?
    int count = Integer.valueOf(expectedCertificates).intValue();
    checkCertificateListForm(caListUrl, count);
  }

  private void checkCertificateListForm(String url, int expectedCertificates) {
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

    String dnName = "CN=" + cnValue + ", OU=" + ouValue + ", O=" + oValue
      + ", L=" + lValue + ", ST=" + stValue + ", C=" + cValue
      + ", T=ca";

    // Set parameters
    request.setParameter( "cadnname", dnName );

    WebResponse response = null;
    try {
      response = wc.getResponse( request );
    }
    catch (Exception e) {
      Assert.fail("Unable to get response for " + url + " Reason: " + e);
    }

    
    String e1[] = {
      "<title>Certificate List</title>",
      "<H2>Certificate List</H2>",
      "<H3>" + String.valueOf(expectedCertificates) + " entries</H3>"
    };
    checkStringsWebResponse(response, e1, null);

    /*
    "/home/u/junittest/UL/cougaar/workspace/security/keystores/caNode/keystore-caNode"
    "/home/u/junittest/UL/cougaar/workspace/security/keystores/caNode/keystore-CONUS-RSA"
    */
  }
}

