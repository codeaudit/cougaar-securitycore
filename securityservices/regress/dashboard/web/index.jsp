<%@page import="java.util.*"%>
<%@page import="java.io.*" %>
<%@page import="java.net.*" %>
<%@page import="java.text.*" %>
<%@page import="javax.servlet.*" %>
<%@page import="javax.servlet.http.*" %>
<%@page import="junit.framework.*" %>
<%@page import="org.cougaar.core.security.dashboard.*" %>
<%@page import="test.org.cougaar.core.security.simul.*" %>
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
  private Dashboard dashboard;

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
<%
    StringBuffer sb = request.getRequestURL();
    try {
      URL url = null;
      url = new URL(new String(sb));
      String s1 = request.getRequestURI();
      String s = url.getProtocol() + "://" + url.getHost() + ":" + url.getPort()
                 + s1.substring(0, s1.lastIndexOf('/')) + "/java.props";
      System.out.println("servlet: " + s);
      dashboard = Dashboard.getInstance();
      dashboard.setJavaPropURL(s);
      dashboard.analyzeResults();
    }
    catch(Exception e) {
      System.out.println("Unable to analyze results" + e);
      e.printStackTrace();
    }
%>
    <center>
    <table>
    <tr>
    <td><img src="./Small_UL_Shield.jpg"></td>
    <td>
    <h1><center><b>The UltraLog NAI Dashboard</b></center></h1>
    <h4><center>Tests summary - Last Analyzis:
    <%=dashboard.getAnalyzisDate() %>
    </center></h4>
    <h4><center>Click <a href="results/html/index.html">here</a> to access the Junit report</center></h4>
    </td>
    <td><img src="./Small_UL_Shield.jpg"></td>
    </tr>
    </table>
    <br><hr>
 
<table cellpadding="2" cellspacing="2" border="1" width="100%">
   <tbody>
     <tr>
       <th valign="top" bgcolor="#ffcc99"><b>Experiment Name<br>
       </b></th>
       <th valign="top" bgcolor="#ffcc99"><b>Node Name<br>
       </b></th>
       <th valign="top" bgcolor="#ffcc99"><b>Errors<br>
       </b></th>
       <th valign="top" bgcolor="#ffcc99"><b>Failures<br>
       </b></th>
       <th valign="top" bgcolor="#ffcc99"><b>Start Time<br>
       </b></th>
       <th valign="top" bgcolor="#ffcc99"><b>Completion Time<br>
       </b></th>
       <th valign="top" bgcolor="#ffcc99"><b>test results log<br>
       </b></th>
       <th valign="top" bgcolor="#ffcc99"><b>log files<br>
       </b></th>
     </tr>

<%
    Vector experiments = dashboard.getExperiments();
    for (int i = 0 ; i < experiments.size() ; i++) {
      Experiment exp = (Experiment) experiments.get(i);
      Vector nodeConfList = exp.getNodeConfiguration();
%>
     <tr>
       <td valign="top" rowspan=<%=(nodeConfList.size() + 1)%>>
         <b><%=exp.getExperimentName()%></b>
       </td>
       <td valign="top">Experiment pre & post operations</td>
       <td valign="top" bgcolor=
<%     if (exp.getTestResult().errorCount() > 0) { %>
       "#ff0000"
<%     } else { %>
       "#33ff33"
<%     } %>
       ><%=String.valueOf(exp.getTestResult().errorCount())%>
       </td>

       <td valign="top" bgcolor=
<%     if (exp.getTestResult().failureCount() > 0) { %>
       "#ff0000"
<%     } else { %>
       "#33ff33"
<%     } %>
       ><%=String.valueOf(exp.getTestResult().failureCount())%>
       </td>

       <td valign="top">
       <%=(new SimpleDateFormat("yyyy.MM.dd-HH:mm:ss")).format(exp.getAnalyzisDate()) %>
       </td>
       <td valign="top"> </td>
       <td valign="top"><%=exp.getJunitResultLink()%></td>
       <td valign="top"> </td>
       </tr>
<%
      /////////////////////////////////////
      // Information about individual nodes
      for (int j = 0 ; j < nodeConfList.size() ; j++) {
        NodeConfiguration nc = (NodeConfiguration) nodeConfList.get(j);
%>
       <tr>
       <td valign="top"><%=String.valueOf(nc.getNodeName())%></td>
       <td valign="top" bgcolor=
<%     if (nc.getErrors() > 0) { %>
       "#ff0000"
<%     } else { %>
       "#33ff33"
<%     } %>
       ><%=String.valueOf(nc.getErrors())%>
       </td>

       <td valign="top" bgcolor=
<%     if (nc.getFailures() > 0) { %>
       "#ff0000"
<%     } else { %>
       "#33ff33"
<%     } %>
       ><%=String.valueOf(nc.getFailures())%>
       </td>

       <td valign="top">
         <%=String.valueOf(nc.getStartTime())%>
       </td>

       <td valign="top">
         <%=String.valueOf(nc.getCompletionTime())%>
       </td>

       <td valign="top"> </td>

       <td valign="top">
         <%=nc.getLogFilesUrls()%>
       </td>

<%
      } // for (int j...
%>
     </tr>
<%
      } // for (int i...
%>
   
  </tbody> 
</table>
<br>
<br>

  </body>
</html>
