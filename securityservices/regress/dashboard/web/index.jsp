<%@page import="java.util.*"%>
<%@ page import="org.cougaar.core.security.dashboard.*" %>
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
    <h4><center>Click <a href="junitreport/index.html">here</a> to access the Junit report</center></h4>
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
	for (int i = 0 ; i < Dashboard.getNumberOfTests() ; i++) {
	  Dashboard.analyzeResults(i);
%>
     <tr>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
         <%=Dashboard.getExperimentName()%>
       </font></td>

       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
         <%=String.valueOf(Dashboard.getErrors())%>
       </font></td>

       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
         <%=String.valueOf(Dashboard.getFailures())%>
       </font></td>

       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>
       <td valign="top"><font face="Helvetica, Arial, sans-serif"><br>
       </font></td>
       <td valign="top"><b><a href="test.html">log</a><br>
       </b></td>
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
