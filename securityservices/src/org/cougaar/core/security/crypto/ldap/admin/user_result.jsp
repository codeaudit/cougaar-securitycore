<%@page import="java.util.*,java.text.*"%>
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
  Map user = (Map) 
    request.getAttribute(UserInterface.USER_RESULTS);
  
  if (user != null) {  
%>
    <form action="<%=request.getRequestURI()%>" method="GET">
      <input type="hidden" name="<%=UserInterface.PAGE%>" 
             value="<%=UserInterface.PAGE_USER_RESULT_ACTION%>">
      <input type="hidden" name="<%=UserInterface.LDAP_USER_UID%>" 
             value="<%=user.get(UserInterface.LDAP_USER_UID)%>">
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
      Object val     = user.get(field);
      if (val == null) val = "";
      if (field.equals(UserInterface.LDAP_USER_ENABLE)) {
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
    }
  }
%>
        <tr>
          <td>Roles</td>
<%
  Set roles = null;
  boolean first = true;
  roles = (Set) request.getAttribute(UserInterface.ROLE_RESULTS);
  Iterator iter = roles.iterator();
  while (iter.hasNext()) {
    String rid = (String) iter.next();
    if (first) {
      first = false;
    } else {
%>
        <tr>
          <td></td>
<%
    }
%>
          <td><%=rid%></td>
        </tr>
<%
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
