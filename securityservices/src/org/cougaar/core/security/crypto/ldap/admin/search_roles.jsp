<%@page import="java.net.*,java.util.*"%>
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
  </head>
  <body>
    <table width="100%">
      <tr>
        <td colspan="3">Roles matching your search:</td>
      </tr>
<%
  Set roles = null;
    roles = (Set) request.getAttribute(UserInterface.SEARCH_RESULTS);
    Iterator iter = roles.iterator();
    while (iter.hasNext()) {
      String rid = (String) iter.next();
%>
      <tr>
        <td>
<a href="<%=request.getRequestURI() + "?" +
              UserInterface.PAGE + "=" + UserInterface.PAGE_DISPLAY_ROLE%>&<%=URLEncoder.encode(UserInterface.LDAP_ROLE_RDN, "UTF-8")%>=<%=URLEncoder.encode(rid, "UTF-8")%>" 
               target="UserMatchFrame"><%=rid%></a>
        </td>
      </tr>
<%
    }
%>
    </table>
  </body>
</html>
