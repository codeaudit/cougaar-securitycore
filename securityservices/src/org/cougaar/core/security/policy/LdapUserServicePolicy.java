/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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

package org.cougaar.core.security.policy;

public class LdapUserServicePolicy extends SecurityPolicy {
  private final static String DEF_UOC[] = { "inetOrgPerson", "cougaarAcct", 
                                            "organizationalPerson" };
  private final static String DEF_ROC[] = { "organizationalRole" };
  
  public String ldapUrl            = "ldap:///";
  public String ldapUser           = null;;
  public String ldapPassword       = null;;
  public String userDN             = "dc=users,dc=cougaar,dc=org";
  public String roleDN             = "dc=roles,dc=cougaar,dc=org";
  public String userRDN            = "uid";
  public String roleRDN            = "cn";
  public String roleAttr           = "roleOccupant";
  public String authAttr           = "cougaarAuthReq";
  public String enableAttr         = "cougaarAcctEnableTime";
  public String passwordAttr       = "userPassword";
  public String certOkAttr         = "certIsSpecial";
  public String userObjectClass[]  = DEF_UOC;
  public String roleObjectClass[]  = DEF_ROC;

  public String toString() {
    StringBuffer buf = 
      new StringBuffer( "LdapUserServicePolicy(" + ldapUrl + "," +
                        ldapUser + "," +
                        (ldapPassword==null ?
                         "null":
                         "*** not displayed ***") + "," +
                        userDN + "," +
                        roleDN + "," +
                        userRDN + "," +
                        roleRDN + "," +
                        enableAttr + "," +
                        authAttr + "," +
                        passwordAttr + "," +
                        certOkAttr + "," +
                        roleAttr + ",[" );
    for (int i = 0; i < userObjectClass.length; i++) {
      if (i != 0) buf.append(',');
      buf.append(userObjectClass[i]);
    }
    buf.append("],[");
    for (int i = 0; i < roleObjectClass.length; i++) {
      if (i != 0) buf.append(',');
      buf.append(roleObjectClass[i]);
    }
    buf.append("])");
    return buf.toString();
  }
}
