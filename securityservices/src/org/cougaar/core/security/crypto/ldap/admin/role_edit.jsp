<%@page import="org.cougaar.core.security.crypto.ldap.admin.UserInterface,java.util.*"%>
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
function cancelAction() {
  history.go(-1);
}
//-->
    </script>
  </head>
  <body>
<%
  Map role = (Map) 
    request.getAttribute(UserInterface.ROLE_RESULTS);
  
  if (role != null) {  
%>
    <form action="<%=request.getRequestURI()%>" method="POST">
      <input type="hidden" name="<%=UserInterface.PAGE%>" 
             value="<%=UserInterface.PAGE_EDIT_ROLE%>">
      <input type="hidden" name="<%=UserInterface.LDAP_ROLE_RDN%>" 
             value="<%=role.get(UserInterface.LDAP_ROLE_RDN)%>">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_SAVE%>">
      <input type="button" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_CANCEL%>"
             onClick="cancelAction()">
      <table>
<%
    for (int i = 0; i < UserInterface.LDAP_ROLE_FIELDS.length; i++) {
      String title   = UserInterface.LDAP_ROLE_FIELDS[i][1];
      String field   = UserInterface.LDAP_ROLE_FIELDS[i][0];
      Object val = role.get(field);
      if (val == null) val = "";
      if (!field.equals(UserInterface.LDAP_ROLE_USER_RDN)) {
%>
        <tr>
          <td><%=title%></td>
          <td><%
        if (field.equals(UserInterface.LDAP_ROLE_RDN)) {
%>
            <%=val%>
<%
        } else {
%>
            <input type="text" name="<%=field%>" value="<%=val%>">
<%
        }
%>        </td>
        </tr>
<%
      }
    }
  }
%>
      </table>
    </form>
  </body>
</html>

