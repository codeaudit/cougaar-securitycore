<%@page import="java.util.*"%>
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
  <head>
    <script language="JavaScript">
<!--
function passwordCheck() {
  var form = document.forms[0];
  if (form["<%=UserInterface.LDAP_USER_PASSWORD%>"].value != 
      form["<%=UserInterface.LDAP_USER_PASSWORD%>-repeat"].value) {
    var span = document.getElementById("error text");
    span.innerHTML = "Passwords must match";
    span = document.getElementById("password1");
    span.setAttribute('style','color: red');
    span = document.getElementById("password2");
    span.setAttribute('style','color: red');
    return false;
  }
  return true;
}
function enableUser() {
  var form = document.forms[0];
  var field = form["<%=UserInterface.LDAP_USER_ENABLE%>"];
  field.value = "19700101000000Z";
}
function disableUser() {
  var form = document.forms[0];
  var field = form["<%=UserInterface.LDAP_USER_ENABLE%>"];
  field.value = "";
}
function updateName() {
  var form = document.forms[0];
  form['cn'].value = form['givenName'].value + ' ' + form['sn'].value;
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
    <form action="<%=request.getRequestURI()%>" method="POST" 
          onSubmit="return passwordCheck();">
      <input type="hidden" name="<%=UserInterface.PAGE%>" 
             value="<%=UserInterface.PAGE_EDIT_USER%>">
      <input type="hidden" name="<%=UserInterface.LDAP_USER_UID%>" 
             value="<%=user.get(UserInterface.LDAP_USER_UID)%>">
      <input type="hidden" name="cn" value="">
      <input type="submit" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_SAVE%>">
      <input type="button" name="<%=UserInterface.ACTION_BUTTON%>" 
             value="<%=UserInterface.ACTION_BUTTON_CANCEL%>"
             onClick="cancelAction()">
      <br><span color="red" id="error text"></span><br>
      <table>
        <tr>
          <td><%=UserInterface.LDAP_USER_UID_TITLE%></td>
          <td><%=user.get(UserInterface.LDAP_USER_UID)%></td>
        </tr>
        <tr>
          <td><span id="password1"><%=UserInterface.LDAP_USER_PASSWORD_TITLE1%></span></td>
          <td><input type="password" 
               name="<%=UserInterface.LDAP_USER_PASSWORD%>" 
               value=""></td>
        </tr>
        <tr>
          <td><span id="password2"><%=UserInterface.LDAP_USER_PASSWORD_TITLE2%></span></td>
          <td><input type="password" 
               name="<%=UserInterface.LDAP_USER_PASSWORD%>-repeat" 
               value=""></td>
        </tr>
<%
    for (int i = 0; i < UserInterface.LDAP_USER_FIELDS.length; i++) {
      String title   = UserInterface.LDAP_USER_FIELDS[i][1];
      String field   = UserInterface.LDAP_USER_FIELDS[i][0];
      Object val     = user.get(field);
      if (val == null) {
        val = "";
      }
      if (field != UserInterface.LDAP_USER_UID && !("cn".equals(field))) {
%>
        <tr>
          <td><%=title%></td>
          <td>
<%
        if (field.equals(UserInterface.LDAP_USER_AUTH)) {
          if ("".equals(val)) val = UserInterface.LDAP_USER_AUTH_VALS[UserInterface.LDAP_USER_AUTH_DEFAULT_VAL][0];
%>
            <select name="<%=field%>">
<%
          for (int j = 0; j < UserInterface.LDAP_USER_AUTH_VALS.length; j++) { 
            String selected = "";
            if (UserInterface.LDAP_USER_AUTH_VALS[j][0].equals(val))
              selected = " selected";
%>
              <option value="<%=UserInterface.LDAP_USER_AUTH_VALS[j][0]%>"
                      <%=selected%> >
                <%=UserInterface.LDAP_USER_AUTH_VALS[j][1]%>
              </option>
<%      } %>
            </select>
<%
        } else if (field.equals(UserInterface.LDAP_USER_ENABLE)) {
%>
          <input type="text" name="<%=field%>" value="<%=val%>">&nbsp;&nbsp;
          <input type="button" value="Enable" onClick="enableUser();">&nbsp;
          <input type="button" value="Disable" onClick="disableUser();">
<%
        } else if (field.equals(UserInterface.LDAP_USER_CERTOK)) {
          boolean certOk = false;
          if (val != null) {
            certOk = Boolean.valueOf(val.toString()).booleanValue();
          }
%>
          <input type="radio" name="<%=field%>" value="TRUE" <%
if (certOk) { out.print("CHECKED"); }
%>>&nbsp;yes&nbsp;
          <input type="radio" name="<%=field%>" value="FALSE" <%
if (!certOk) { out.print("CHECKED"); }
%>>&nbsp;no
<%
        } else if ("sn".equals(field) || "givenName".equals(field)) {
%>
          <input type="text" name="<%=field%>" value="<%=val%>" onChange="updateName()">
<%
        } else {
%>
          <input type="text" name="<%=field%>" value="<%=val%>">
<%
        }
%>
          </td>
        </tr>
<%
      }
    }
  }
%>
      </table>
    </form>
    <script language="JavaScript">
<!--
  updateName();
//-->
    </script>
  </body>
</html>
