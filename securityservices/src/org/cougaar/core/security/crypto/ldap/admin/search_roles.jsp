<%@page import="javax.naming.*,javax.naming.directory.*,java.net.*"%>
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
  <body>
    <table width="100%">
      <tr>
        <td colspan="3">Roles matching your search:</td>
      </tr>
<%
  NamingEnumeration roles = null;
  try {
    roles = (NamingEnumeration) request.getAttribute(UserInterface.SEARCH_RESULTS);
%>
      <tr>
<%
    for (int i = 0; i < UserInterface.LDAP_ROLE_SEARCH_FIELDS.length; i++) {
%>
        <td><b><%=UserInterface.LDAP_ROLE_SEARCH_FIELDS[i][1]%></b></td>
<%
    }
%>
      </tr>
<%
    while (roles.hasMore()) {
%>
      <tr>
<%
      SearchResult role = (SearchResult) roles.next();
      Attributes attrs = role.getAttributes();
      String rid = attrs.get(UserInterface.LDAP_ROLE_RDN).get().toString();
      for (int i = 0; i < UserInterface.LDAP_ROLE_SEARCH_FIELDS.length; i++) {
        Attribute attr = attrs.get(UserInterface.LDAP_ROLE_SEARCH_FIELDS[i][0]);
        String val = "";
        if (attr != null) val = attr.get().toString();
%>
        <td>
<% 
        if (i == 0) {
%><a href="<%=request.getRequestURI() + "?" +
              UserInterface.PAGE + "=" + UserInterface.PAGE_DISPLAY_ROLE%>&<%=URLEncoder.encode(UserInterface.LDAP_ROLE_RDN)%>=<%=URLEncoder.encode(rid)%>" 
               target="UserMatchFrame"><%
        } 
%><%=val%><%
        if (i == 1) {
%></a><%
        }
%></td>
<%
      }
%>
      </tr>
<%
    }
  } catch (NamingException ne) {
    if (roles != null) {
      roles.close();
    }
  }
%>
    </table>
  </body>
</html>
