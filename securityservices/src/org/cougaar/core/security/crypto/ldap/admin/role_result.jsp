<%@page import="javax.naming.*,javax.naming.directory.*"%>
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
  return confirm("Really delete this role?");
}
// -->
    </script>
  </head>
  <body>
<%
  Attributes role = (Attributes) 
    request.getAttribute(UserInterface.ROLE_RESULTS);
  
  if (role != null) {  
%>
    <form action="<%=request.getRequestURI()%>" method="GET">
     <input type="hidden" name="<%=UserInterface.PAGE%>" 
            value="<%=UserInterface.PAGE_ROLE_RESULT_ACTION%>">
     <input type="hidden" name="<%=UserInterface.LDAP_ROLE_RDN%>" 
             value="<%=role.get(UserInterface.LDAP_ROLE_RDN).get()%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_EDIT%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_COPY%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_DELETE%>"
             onClick="return deleteCheck();">
      <table>
<%
    for (int i = 0; i < UserInterface.LDAP_ROLE_FIELDS.length; i++) {
      String title   = UserInterface.LDAP_ROLE_FIELDS[i][1];
      String field   = UserInterface.LDAP_ROLE_FIELDS[i][0];
      Attribute attr = role.get(field);
      Object val     = null;
      int size = 0;
      if (attr != null) {
        val = attr.get();
        size = attr.size();
      }
//      if (val == null || val.equals(UserInterface.LDAP_ROLE_DUMMY)) val = "";
      if (val == null) val = "";
%>
        <tr>
          <td><%=title%></td>
          <td><%=val%></td>
        </tr>
<%
      for (int j = 1; j < size; j++) {
//        if (!attr.get(j).equals(UserInterface.LDAP_ROLE_DUMMY)) {
%>
        <tr>
          <td></td>
          <td><%=attr.get(j)%></td>
        </tr>
<%
//        }
      }
    }
  }
%>
      </table>
    </form>
  </body>
</html>
