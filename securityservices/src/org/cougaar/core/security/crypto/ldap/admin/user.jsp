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
    <title>User Edit</title>
<script language="JavaScript">
function newUser() {
  top.frames['UserMatchFrame'].location.href='<%=request.getRequestURI() + "?" + UserInterface.PAGE + "=" + UserInterface.PAGE_NEW_USER_JSP%>';
}
</script>
  </head>

  <body>
    <table width="100%">
      <tr>
        <td align="right"><b>Users</b></td>
        <td align="center">|</td>
        <td align="left"><a href="<%=request.getRequestURI() + "?" +
                     UserInterface.PAGE + "=" + 
                     UserInterface.PAGE_SEARCH_ROLE%>">Roles</a></td>
      </tr>
    </table>
    <form action="<%=request.getRequestURI()%>"
          target="SearchResultsFrame" method="GET">
      <input type="hidden" name="<%=UserInterface.PAGE%>" 
             value="<%=UserInterface.PAGE_RESULTS_USER%>">
      <table width="100%">
        <tr>
          <td>Search Term</td>
          <td><input type="text" name="<%=UserInterface.SEARCH_TERM%>"></td>
        </tr>
        <tr>
          <td>Search On</td>
          <td>
            <select name="<%=UserInterface.SEARCH_FIELD%>">
<% for (int i = 0; i < UserInterface.LDAP_USER_FIELDS.length; i++) {
     String ldapName = UserInterface.LDAP_USER_FIELDS[i][0];
     String visName = UserInterface.LDAP_USER_FIELDS[i][1];
%>
              <option value="<%=ldapName%>"><%=visName%></option>
<% } %>
            </select>
          </td>
        </tr>
        <tr>
          <td>Maximum Results</td>
          <td>
            <select name="<%=UserInterface.SEARCH_MAX_RESULTS%>">
              <option value="10">10</option>
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100" selected>100</option>
              <option value="200">200</option>
              <option value="500">500</option>
            </select>
          </td>
        </tr>
        <tr>
          <td align="left">
            <input type="button" value="<%=UserInterface.ACTION_BUTTON_NEW%>" 
                   onClick="newUser()">
          </td>
          <td align="right">
            <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>"
             value="<%=UserInterface.ACTION_BUTTON_SEARCH%>">
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>
