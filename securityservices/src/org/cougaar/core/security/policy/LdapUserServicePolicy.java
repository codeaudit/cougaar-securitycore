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
