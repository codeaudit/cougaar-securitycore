/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 4:01 PM
 */

package org.cougaar.core.security.services.crypto;

import org.cougaar.core.component.Service;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.ModificationItem;

public interface LdapUserService extends Service {
  
  public NamingEnumeration getUsers(String searchText, String field,
                                    int maxResults) 
    throws NamingException ;
  public NamingEnumeration getUsers(String filter, int maxResults)
    throws NamingException ;
  public Attributes        getUser(String uid) 
    throws NamingException ;
  public void              editUser(String uid, ModificationItem[] mods) 
    throws NamingException ;
  public void              addUser(String uid, Attributes attrs) 
    throws NamingException ;
  public void              deleteUser(String uid) 
    throws NamingException ;

  public NamingEnumeration getRoles(String uid) 
    throws NamingException ;
  public NamingEnumeration getRoles(String searchText, int maxResults) 
    throws NamingException ;
  public NamingEnumeration getRoles(int maxResults) 
    throws NamingException ;
  public Attributes        getRole(String rid) 
    throws NamingException ;
  public void              assign(String uid, String rid) 
    throws NamingException ;
  public void              unassign(String uid, String rid) 
    throws NamingException ;
  public void              addRole(String rid) 
    throws NamingException ;
  public void              deleteRole(String rid) 
    throws NamingException ;
}
