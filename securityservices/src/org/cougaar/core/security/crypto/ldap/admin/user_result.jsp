<%@page import="javax.naming.*,javax.naming.directory.*,java.util.*,java.text.*"%>
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
    <script language="JavaScript">
<!--
function deleteCheck() {
  return confirm("Really delete this user?");
}
// -->
    </script>
  </head>
  <body>
<%
  Attributes user = (Attributes) 
    request.getAttribute(UserInterface.USER_RESULTS);
  
  if (user != null) {  
%>
    <form action="<%=request.getRequestURI()%>" method="GET">
      <input type="hidden" name="<%=UserInterface.PAGE%>" 
             value="<%=UserInterface.PAGE_USER_RESULT_ACTION%>">
      <input type="hidden" name="<%=UserInterface.LDAP_USER_UID%>" 
             value="<%=user.get(UserInterface.LDAP_USER_UID).get()%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_EDIT%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_COPY%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_ASSIGN_ROLES%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_DELETE%>"
             onClick="return deleteCheck();">
      <table>
<%
    for (int i = 0; i < UserInterface.LDAP_USER_FIELDS.length; i++) {
      String title   = UserInterface.LDAP_USER_FIELDS[i][1];
      String field   = UserInterface.LDAP_USER_FIELDS[i][0];
      Attribute attr = user.get(field);
      Object val     = null;
      int size = 0;
      if (attr != null) {
        val = attr.get();
        size = attr.size();
      }
      if (val == null) val = "";
      if (field == UserInterface.LDAP_USER_ENABLE) {
        String str = val.toString();
        Calendar now = null;
        now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        String nowStr = df.format(now.getTime());
        if (str.length() == 0) {
          val = "<span style=\"color: red\">Disabled Account</span>";
        } else if (nowStr.compareToIgnoreCase(str) < 0) {
          val = "<span style=\"color: red\">" + val + "</span>";
        }
      }
%>
        <tr>
          <td><%=title%></td>
          <td><%=val%></td>
        </tr>
<%
      for (int j = 1; j < size; j++) {
%>
        <tr>
          <td></td>
          <td><%=attr.get(j)%></td>
        </tr>
<%
      }
    }
  }
%>
        <tr>
          <td>Roles</td>
<%
  NamingEnumeration roles = null;
  boolean first = true;
  try {
    roles = (NamingEnumeration) request.getAttribute(UserInterface.ROLE_RESULTS);
    while (roles.hasMore()) {
      SearchResult sr = (SearchResult) roles.next();
      Attributes attrs = sr.getAttributes();
      Attribute attr = attrs.get(UserInterface.LDAP_ROLE_RDN);
      Object val = "";
      if (attr != null) {
        val = attr.get();
      }
      if (first) {
        first = false;
      } else {
%>
        <tr>
          <td></td>
<%
      }
%>
          <td><%=val%></td>
        </tr>
<%
    }
  } catch (NamingException ne) {
    ne.printStackTrace();
    if (roles != null) roles.close();
  }
  if (first) { // no roles assigned to this user
%>
     <td></td></tr>    
<%
  }
%>
      </table>
    </form>
  </body>
</html>
