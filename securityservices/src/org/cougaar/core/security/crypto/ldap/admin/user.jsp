<%
/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    <META http-equiv="Content-Type" content="text/html; charset=US-ASCII">
    <title>User Edit</title>
<script language="JavaScript">
function newUser() {
  top.frames['UserMatchFrame'].location.href='<%=request.getRequestURI() + "?" + UserInterface.PAGE + "=" + UserInterface.PAGE_NEW_USER_JSP%>';
}
function saveUsers() {
  top.frames['UserMatchFrame'].location.href='<%=request.getRequestURI() + "?" + UserInterface.PAGE + "=" + UserInterface.PAGE_SAVE_USERS_JSP%>';
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
          <td align="center">
            <input type="submit" name="<%=UserInterface.ACTION_BUTTON_SAVE_USERS%>"
             onClick="saveUsers()">
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
