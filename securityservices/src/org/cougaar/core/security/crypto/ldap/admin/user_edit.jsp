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
  Attributes user = (Attributes) 
    request.getAttribute(UserInterface.USER_RESULTS);

  if (user != null) {  
%>
    <form action="<%=request.getRequestURI()%>" method="POST" 
          onSubmit="return passwordCheck();">
      <input type="hidden" name="<%=UserInterface.PAGE%>" 
             value="<%=UserInterface.PAGE_EDIT_USER%>">
      <input type="hidden" name="<%=UserInterface.LDAP_USER_UID%>" 
             value="<%=user.get(UserInterface.LDAP_USER_UID).get()%>">
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
          <td><%=user.get(UserInterface.LDAP_USER_UID).get()%></td>
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
      Attribute attr = user.get(field);
      Object val     = "";
      if (attr != null) {
        val = attr.get();
      }
      if (field != UserInterface.LDAP_USER_UID && !("cn".equals(field))) {
%>
        <tr>
          <td><%=title%></td>
          <td>
<%
        if (field == UserInterface.LDAP_USER_AUTH) {
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
        } else if (field == UserInterface.LDAP_USER_ENABLE) {
%>
          <input type="text" name="<%=field%>" value="<%=val%>">&nbsp;&nbsp;
          <input type="button" value="Enable" onClick="enableUser();">&nbsp;
          <input type="button" value="Disable" onClick="disableUser();">
<%
        } else if (field == UserInterface.LDAP_USER_CERTOK) {
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
