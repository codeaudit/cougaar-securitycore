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

package org.cougaar.core.security.certauthority.servlet;

import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.security.*;
import java.security.cert.*;
import java.math.BigInteger;
import sun.security.x509.*;
import sun.security.util.*;
import sun.security.pkcs.*;

import org.w3c.dom.*;

// Cougaar core infrastructure
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.services.util.*;
import org.cougaar.core.security.services.crypto.CertificateManagementService;
import org.cougaar.core.security.services.crypto.CertificateManagementServiceClient;
import org.cougaar.core.security.certauthority.*;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.crypto.Base64;

public class BrowserSigningRequest
  extends  HttpServlet
{
  private CertificateManagementService signer;
  private SecurityServletSupport support;
  private ConfigParserService configParser = null;
  private LoggingService log;
  private X500Name[] caDNs = null;

  public BrowserSigningRequest(SecurityServletSupport support) {
    if (support == null) {
      throw new IllegalArgumentException("Support services null");
    }
    this.support = support;
    log = (LoggingService)
	support.getServiceBroker().getService(this,
	LoggingService.class, null);
  }

  public void init(ServletConfig config) throws ServletException
  {
    super.init(config);
    try {
      configParser = (ConfigParserService)
	support.getServiceBroker().getService(this,
					      ConfigParserService.class,
					      null);
      caDNs = configParser.getCaDNs();
    }
    catch (RuntimeException e) {
      if (log.isErrorEnabled()) {
	log.error("Unable to initialize servlet: " + e.toString());
	e.printStackTrace();
      }
      throw e;
    }
  }

  private X500Name getUserName(String userid, String caDN) throws IOException {
    X500Name caName = new X500Name(caDN);
    StringBuffer userDN = new StringBuffer();
    userDN.append("cn=").append(userid);
    String attrs[][] = new String[][] {
      { caName.getOrganizationalUnit(), "ou" },
      { caName.getOrganization(), "o" },
      { caName.getLocality(), "l" },
      { caName.getState(), "st" },
      { caName.getCountry(), "c" }
    };
    for (int i = 0; i < attrs.length; i++) {
      if (attrs[i][0] != null) {
        userDN.append(',').append(attrs[i][1]).append('=').append(attrs[i][0]);
      } // end of if (attrs[i][0] != null)
    } // end of for (int i = 0; i < attrs.length; i++)
    X500Name userName = new X500Name(userDN.toString());
    return userName;
  }

  private PKCS10 getCertReq(String userid, //String emailAddress, 
                            String b64PubKey, String caDN) 
    throws IOException, NoSuchAlgorithmException,CertificateEncodingException {
    byte[] derEnc = Base64.decode(b64PubKey.toCharArray());
    DerValue der = new DerValue(derEnc);
    DerValue spki = der.data.getDerValue();
    if (spki.tag != 48) {
      log.debug("Browser certificate is not valid -- invalid SubjectPublicKeyInfo");
      return null;
    } // end of if (spki.tag != 48)
    
    PublicKey pubKey = X509Key.parse(spki.data.getDerValue());
    AlgorithmId algorithmid = AlgorithmId.get(pubKey.getAlgorithm());
    
    // FIXME: I should verify the signature, but I'm a little lazy right now
//     String challenge = spki.data.getIA5String();

    X500Name user = getUserName(userid, caDN);
    return new MyPKCS10(pubKey, user);
  }

  private void sendCertResponse(CertificateResponse cr, HttpServletResponse resp,
                                boolean isIE) 
    throws IOException, CertificateEncodingException {
    boolean multipart = false;
    long boundary = System.currentTimeMillis();
    PrintWriter out = resp.getWriter();
    if (cr.cert != null) {
      multipart = true;
      byte[] encoded = cr.cert.getEncoded();
      char[] b64 = Base64.encode(encoded);
      StringBuffer certBuf = new StringBuffer();
      certBuf.append("-----BEGIN CERTIFICATE-----\n");
      certBuf.append(b64);
      certBuf.append("\n-----END CERTIFICATE-----\n");
      String textCert = certBuf.toString();
      resp.reset();
      if (!isIE) {
        resp.setContentType("multipart/x-mixed-replace;boundary=" + boundary);
        out.println("--" + boundary);
        out.println("Content-type: application/x-x509-user-cert");
        out.println("Content-length: " + textCert.length());
        out.println();
      } else {
        resp.setContentType("application/x-x509-user-cert");
        resp.setHeader("Content-Disposition","inline; filename=\"user.cer\"");
      } // end of else
      out.print(textCert);
      if (isIE) {
        return;
      } // end of if (isIE)
      out.println("--" +boundary);
      out.println("Content-type: text/html");
      out.println();
    } else {
      resp.setContentType("text/html");
    } // end of if (resp.cert != null)else
    out.println("<html>");
    out.println("<head><title>Browser Certificate Signing Response</title></head>");
    out.println("<body>");
    String status;
    switch (cr.status) {
    case KeyManagement.PENDING_STATUS_APPROVED:
      status = "Your certificate has been approved and loaded into your browser";
      break;
    case KeyManagement.PENDING_STATUS_PENDING:
      status = "Certificate is pending for approval.";
      break;
    case KeyManagement.PENDING_STATUS_DENIED:
      status = "Certificate is denied by CA.";
      break;
    case KeyManagement.PENDING_STATUS_NEW:
      status = "Certificate has been sent to the CA for approval.";
      break;
    default:
      status = "Error getting the status.";
      break;
    } // end of switch (resp.status)
    out.println(status);
    out.println("</body></html>");
    if (multipart) {
      out.println("--" + boundary + "--");
    } // end of if (multipart)
  }

  public void sendError(HttpServletResponse res, String message) throws IOException {
    res.setContentType("text/html");
    PrintWriter out = res.getWriter();
    out.println("<html><body><h1>Error</h1>");
    out.println(message);
    out.println("</body></html>");
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    if (log.isDebugEnabled()) {
      log.debug("Received a browser certificate signing request");
    }
    String base64PubKey = req.getParameter("SPKAC");
    String userId = req.getParameter("userid");
    String caDN = req.getParameter("dnname");
    try {
      PKCS10 certReq;
      if (base64PubKey != null) {
        certReq = getCertReq(userId, base64PubKey, caDN);
      } else {
        certReq = MyPKCS10.createPKCS10(req.getParameter("pkcsdata"));
      } // end of else
      

      if (caDN == null || caDN.length() == 0) {
        if (log.isDebugEnabled()) {
          log.debug("Error -- Unknown CA dn name: " + caDN);
        } // end of if (log.isDebugEnabled())
        
	sendError(res,"Error ---Unknown  type CA dn name " + caDN);
	return;
      }
      try  {
	signer =
	  (CertificateManagementService)support.getServiceBroker().getService(
	    new CertificateManagementServiceClientImpl(caDN),
	    CertificateManagementService.class, null);
      } catch (Exception exp)  {
        log.debug("Error signing browser certificate", exp);
        sendError(res,"Error ---" + exp.toString());
	return;
      }

      try  {
        CertificateResponse certResp = signer.processPkcs10Request(certReq);

        sendCertResponse(certResp, res, base64PubKey == null);
      }
      catch (Exception  exp)  {
        log.debug("Caught an exception when trying to sign: ", exp);
        sendError(res,"Error ------" + exp.toString());
        return;
      }
    }
    catch (Exception e1) {
      log.debug("Error when processing browser signing request", e1);
      sendError(res,"Error when processing request: " + e1);
    }
  }

  protected void doGet(HttpServletRequest req,
		       HttpServletResponse res)
    throws ServletException, IOException  {
    if (req.getParameter("vbscript") != null) {
      vbScript(res);
      return;
    } // end of if (req.getParameter("vbscript") != null)
    
    if (log.isDebugEnabled()) {
      log.debug("+++++ Certificate signing request: ");
      log.debug("method:" + req.getMethod());
      log.debug("authType:" + req.getAuthType());
      log.debug("pathInfo:" + req.getPathInfo());
      log.debug("query:" + req.getQueryString());
    }

    String userAgent = req.getHeader("user-agent");
    boolean isIE = (userAgent != null &&
                    userAgent.indexOf("MSIE") != -1);

    res.setContentType("text/html");
    PrintWriter out=res.getWriter();

    out.println("<html>");
    out.println("<head>");
    out.println("<title>Browser Signing Request </title>");
    String onSubmit = "";
    if (isIE) {
      out.println("<script type=\"text/vbscript\" src=\"BrowserSigningRequest?vbscript=true\"></script>");
      onSubmit = "onSubmit=\"myenroll.CreateP10()\"";
    } // end of if (isIE)
    
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>Browser Signing Request</H2>");
    if (isIE) {
      out.println("<object classid=\"clsid:43F8F289-7A20-11D0-8F06-00C04FC295E1\" " +
                  "codebase=\"file:///WINDOWS/SYSTEM32/xenroll.dll\" id=\"cenroll\">" +
                  "This isn't internet explorer! You can't create a certificate " + 
                  "with this browser</object>");
    } // end of if (isIE)
    out.println("<form name=\"MyForm\" id=\"MyForm\" action=\"BrowserSigningRequest\" method =\"post\" " + onSubmit + ">");
    out.println("<table>");
    out.println("<tr><td align=right>");

    // CA
    out.println("Select CA:</td><td align=left><select id=\"dnname\" name=\"dnname\">");
    for (int i = 0 ; i < caDNs.length ; i++) {
      out.println("<option value=\"" + caDNs[i].toString() + "\">" 
		  + caDNs[i].toString() + "</option>");
    }
    out.println("</select>");

    out.println("</td></tr>");
    out.println("<tr><td align=right>User Id</td><td align=left><input type=text name=userid></td></tr>");
    out.println("<tr><td align=right>");
    long challenge = (long)(Math.random() * Long.MAX_VALUE);
    if (isIE) {
      out.print("Cryptographic Service Provider</td><td align=left>" +
                "<select name=cspName id=cspName></select>" + 
                "<input type=hidden name=pkcsdata>" + 
                "<input type=hidden name=pkcs value=pkcs10>" + 
                "<input type=hidden name=replyformat value=html>");
    } else {
      out.print("Select the key size:</td><td align=left><keygen name=SPKAC challenge=");
      out.print(challenge);
      out.println(">");      
    } // end of if (isIE)else
    out.println("</td></tr>");
    if (!isIE) {
      out.println("<tr><td colspan=2>Please note that the Schlumberger " +
                  "<b>smart cards only support 1024 bit keys</b>, so please " +
                  "select 1024 bits if you are using a smart card.</td></tr>");
    } // end of if (!isIE)
    out.println("<tr><td align=right><input type=\"submit\" value=\"Get Certificate\">");
    out.println("<td align=left><input type=\"reset\"></td></tr>");
    out.println("</table>");
    out.println("<input type=hidden name=challenge value=" + challenge + ">");
    if (isIE) {
      out.println("<script type=\"text/vbscript\">");
      out.println("<!--");
      out.println("Set myenroll=new Enroll");
      out.println("myenroll.FindProviders");
      out.println("' -->");
      out.println("</script>");
      out.println("<noscript>");
      out.println("<p class=\"errmsg\">VBScript must be enabled!</p>");
      out.println("</noscript>");
    } // end of if (isIE)
    out.println("</form>");
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  private void vbScript(HttpServletResponse resp) throws IOException {
    resp.setContentType("text/vbscript");
    PrintWriter out = resp.getWriter();
    
    out.print("Option Explicit\n" +
              "\n" +
              "Class Enroll\n" +
              "  Private Form\n" +
              "  Private DN\n" +
              "\n" +
              "  Private Sub Class_Initialize()\n" +
              "    Set Form = Document.MyForm\n" +
              "  End Sub\n" +
              "\n" +
              "  Public Sub FindProviders()\n" +
              "    Dim i, j, cspOption, csp, DefaultKeySize\n" +
              "    Const enumFlags = 0\n" +
              "    On Error Resume Next\n" +
              "\n" +
              "    i = 0\n" +
              "    j = 1\n" +
              "    DefaultKeySize = 0\n" +
              "    cenroll.providerType = 1\n" +
              "    Do\n" +
              "      csp = \"\"\n" +
              "      csp = cenroll.enumProviders(i, enumFlags)\n" +
              "      If Len(csp) = 0 Then\n" +
              "        Exit Do\n" +
              "      End If\n" +
              "      set cspOption = document.createElement(\"option\")\n" +
              "      cspOption.text = csp\n" +
              "      cspOption.value = csp\n" +
              "      Form.cspName.add(cspOption)\n" +
              "      i = i + 1\n" +
              "      j = j + 1\n" +
              "    Loop\n" +
              "    Form.cspName.selectedIndex = DefaultKeySize\n" +
              "  End Sub\n" +
              "\n" +
              "  Private Sub FieldErr(f)\n" +
              "    f.Focus\n" +
              "    Alert \"Error: \" & f.id & \" is empty or illegal\"\n" +
              "  End Sub\n" +
              "\n" +
              "  Public Function CreateP10()\n" +
              "    Dim keyprov, key, prov, pkcs10data, GenKeyFlags\n" +
              "    Const CRYPT_EXPORTABLE=1\n" +
              "    Const CRYPT_USER_PROTECTED=2\n" +
              "    Const usage = \"\"\n" +
              "    CreateP10 = False\n" +
              "    If ChangeDN = False Then\n" +
              "      Exit Function\n" +
              "    End If\n" +
              "    prov = Form.cspName.value\n" +
              "    GenKeyFlags = 0\n" +
              "    cenroll.providerName = prov\n" +
              "    cenroll.EnableT61DNEncoding = True\n" +
              "    On Error Resume Next\n" +
              "    pkcs10data = cenroll.createPKCS10(DN, usage)\n" +
              "    If pkcs10data = Empty Then\n" +
              "      CreateP10 = False\n" +
              "      Alert \"Error \" & Hex(Err) & \": Your credentials could not be generated.\"\n" +
              "      Exit Function\n" +
              "    End If\n" +
              "    CreateP10 = True\n" +
              "    Form.pkcsdata.value = pkcs10data\n" +
              "  End Function\n" +
              "\n" +
              "  Private Function AddToDN(name, value)\n" +
              "    AddToDN = True\n" +
              "    If ((name = \"T\") or (name = \"t\") or (name = \"CN\") or (name = \"cn\")) Then\n" +
              "      Exit Function\n" +
              "    End If\n" +
              "    DN = DN & \",\" & name & \"=\" & value\n" +
              "  End Function\n" +
              "\n" +
              "  Public Function ChangeDN()\n" +
              "    Dim val, name, value, eq, com, c, i\n" +
              "    ChangeDN = True\n" +
              "    DN = \"CN=\" & Form.userid.value\n" +
              "    val = Form.dnname.value\n" +
              "    com = 0\n" +
              "    For i = 1 to Len(val)\n" +
              "      c = Mid(val, i, 1)\n" +
              "      If c = \" \" and com = i - 1 Then\n" +
              "        com = com + 1\n" +
              "      End If  \n" +
              "      If c = \"=\" Then\n" +
              "        eq = i\n" +
              "      End If  \n" +
              "      If c = \",\" Then\n" +
              "        name = Mid(val, com + 1, eq - com - 1)\n" +
              "        value = Mid(val, eq + 1, i - eq - 1)\n" +
              "        If AddToDN(name, value) = False Then\n" +
              "          rem name=\"foo\"\n" +
              "        End If\n" +
              "        com = i\n" +
              "      End If\n" +
              "    Next\n" +
              "    name = Mid(val, com + 1, eq - com - 1)\n" +
              "    value = Mid(val, eq + 1, i - eq - 1)\n" +
              "    If AddToDN(name,value) = False Then\n" +
              "      rem name=\"foo\"\n" +
              "    End If\n" +
              "  End Function\n" +
              "\n" +
              "End Class\n" +
              "\n" +
              "Dim myenroll\n");
  }
  public String getServletInfo()
  {
    return("Accepts signing request and returns signed certificate");
  }

  private class CertificateManagementServiceClientImpl
    implements CertificateManagementServiceClient
  {
    private String caDN;
    public CertificateManagementServiceClientImpl(String aCaDN) {
      caDN = aCaDN;
    }
    public String getCaDN() {
      return caDN;
    }
  }

  private static class MyPKCS10 extends PKCS10 {
    X500Name _subject;
    public MyPKCS10(PublicKey pubKey, X500Name subject) {
      super(pubKey);
      _subject = subject;
    }

    /**
     * Create a PKCS10 object from a Base-64 encoded Certificate Signing Request.
     */
    public static PKCS10 createPKCS10(String b64)
      throws IOException, SignatureException, NoSuchAlgorithmException {
      byte bytes[] = Base64.decode(b64.toCharArray());
      DerInputStream derinputstream = new DerInputStream(bytes);
      DerValue adervalue[] = derinputstream.getSequence(3);
      if(adervalue.length != 3)
        throw new IllegalArgumentException("not a PKCS #10 request");
      bytes = adervalue[0].toByteArray();
      AlgorithmId algorithmid = AlgorithmId.parse(adervalue[1]);
      byte sig[] = adervalue[2].getBitString();
      BigInteger bigint = adervalue[0].data.getBigInteger();
      if(bigint.intValue() != 0) {
        throw new IllegalArgumentException("not PKCS #10 v1");
      }

      X500Name subject = new X500Name(adervalue[0].data);
      PublicKey pubKey = X509Key.parse(adervalue[0].data.getDerValue());
      try {
        Signature signature = Signature.getInstance(algorithmid.getName());
        signature.initVerify(pubKey);
        signature.update(bytes);
        if(!signature.verify(sig))
          throw new SignatureException("Invalid PKCS #10 signature");
        return new MyPKCS10(pubKey, subject);
      } catch(InvalidKeyException invalidkeyexception) {
        throw new SignatureException("invalid key");
      }
    }

    public X500Name getSubjectName() {
      return _subject;
    }
  }
}
