<%@page import="java.util.*"%>
<%@page import="java.io.*" %>
<%@page import="java.net.*" %>
<%@page import="javax.servlet.*" %>
<%@page import="javax.servlet.http.*" %>
<%@page import="org.cougaar.core.security.dashboard.*" %>
<%
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
%>

<%!
  public void jspInit() {
  }
   	
  public void jspDestroy() {      
  }
%>

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
     <META http-equiv="Content-Type" content="text/html; charset=US-ASCII">
     <title>Junit NAI Dashboard</title>
  </head>
  <body>
    <center>
    <table>
    <tr>
    <td><img src="./Small_UL_Shield.jpg"></td>
    <td>
    <h1><center><b>The UltraLog NAI Dashboard</b></center></h1>
    <h4><center>Tests summary</center></h4>
    <h4><center>Click <a href="results/html/index.html">here</a> to access the Junit report</center></h4>
    </td>
    <td><img src="./Small_UL_Shield.jpg"></td>
    </tr>
    </table>
    <br><hr>
 
<table cellpadding="2" cellspacing="2" border="1" width="100%">
   <tbody>
     <tr>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>Name<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>Errors<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>Failures<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>Time<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>Completion Time<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>cvs log<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>build log<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>test results log<br>
       </b></font></th>
       <th valign="top" bgcolor="#ffcc99"><font face="Helvetica, Arial, sans-serif"><b>log files<br>
       </b></font></th>
     </tr>

<%
    StringBuffer sb = request.getRequestURL();
    try {
      URL url = null;
      url = new URL(new String(sb));
      String s1 = request.getRequestURI();
      String s = url.getProtocol() + "://" + url.getHost() + ":" + url.getPort() + s1.substring(0, s1.lastIndexOf('/')) + "/java.props";
      System.out.println("servlet: " + s);
      Dashboard.setJavaPropURL(s);
      Dashboard.analyzeResults();
    }
    catch(Exception e) {
      System.out.println("Unable to analyze results" + e);
      e.printStackTrace();
    }
    for (int i = 0 ; i < Dashboard.getNumberOfTests() ; i++) {
%>
     <tr>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
         <%=Dashboard.getExperimentName(i)%>
       </font></td>

       <td valign="top" bgcolor=
<%
       if (Dashboard.getErrors(i) > 0) {
%>
       "#ff0000"
<%
       } else {
%>
       "#33ff33"
<%
       }
%>
       ><font face="Helvetica, Arial, sans-serif"><br>
         <%=String.valueOf(Dashboard.getErrors(i))%>
       </font></td>

       <td valign="top" bgcolor=
<%
       if (Dashboard.getFailures(i) > 0) {
%>
       "#ff0000"
<%
       } else {
%>
       "#33ff33"
<%
       }
%>
       ><font face="Helvetica, Arial, sans-serif"><br>
         <%=String.valueOf(Dashboard.getFailures(i))%>
       </font></td>

       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
         <%=String.valueOf(Dashboard.getCompletionTime(i))%>
       </font></td>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>

       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
         <%=Dashboard.getResultLogFileUrls(i)%>
       </font></td>

       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
         <%=Dashboard.getLogFileUrls(i)%>
       </font></td>

     </tr>
<%
	}
%>
   
  </tbody> 
</table>
<br>
<br>

  </body>
</html>
