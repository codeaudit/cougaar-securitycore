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

public interface LdapUserService
  extends Service
{

  /**
   * Returns the user attribute used for comparing passwords
   */
  public String getPasswordAttribute();

  /**
   * Returns the role attribute used to insert a user into a role
   */
  public String getUserRoleAttribute();

  /**
   * Returns the user attribute used to check whether certificates,
   * password, either, or both are required to login.
   * <p>
   * Possible values are:
   * <ul>
   *  <li>"EITHER"
   *  <li>"CERT"
   *  <li>"PASSWORD"
   *  <li>"BOTH"
   * </ul>
   * A <code>null</code> value should be considered as "EITHER".
   */
  public String getAuthFieldsAttribute();

  /**
   * Returns the user attribute that governs when the account should
   * be enabled. 
   *
   * A <code>null</code> entry or one with a value greater than
   * the current time should be considered as a disabled (user cannot
   * login) account.
   * <p>
   * Note that the format of this field is standard LDAP time, so
   * expect something like "200210210430Z" where the time is in
   * GMT.
   */
  public String getEnableTimeAttribute();

  /**
   * Returns the user attribute to use for distinguishing users
   * from one another, such as "uid".
   */
  public String getUserIDAttribute();

  /**
   * Returns the role attribute used to distinguish roles from
   * one another, such as "cn".
   */
  public String getRoleIDAttribute();

  /**
   * Disables a user by removing a value from the enable time
   * attribute in the LDAP user database.
   *
   * @param uid The unique user identifier of the user to disable
   * @throw javax.naming.NamingException Whenever the uid does not
   *        exist or the enable time attribute value is already empty.
   *        Also if there is no write access to the user account specified.
   */
  public void disableUser(String uid) throws NamingException;

  /**
   * Disables a user for the given amount of time
   *
   * @param uid The unique user identifier of the user to disable
   * @param milliseconds The amount of time to disable the user in
   *        milliseconds.
   * @throw javax.naming.NamingException Whenever the uid does not
   *        exist or if there is no write access to the user account specified.
   */
  public void disableUser(String uid, long milliseconds) 
    throws NamingException;

  /**
   * Enables a user who has been disabled
   *
   * @param uid The unique user identifier of the user to enable
   * @throw javax.naming.NamingException Whenever the uid does not
   *        exist or if there is no write access to the user account specified.
   */
  public void enableUser(String uid) 
    throws NamingException;

  /**
   * Returns a <code>NamingEnumeration</code> containing
   * <code>SearchResult</code>s. You must close the NamingEnumeration
   * if you don't traverse the entire thing.
   *
   * @param searchText The text to search for in the field
   * @param field The ldap attribute name to search in
   * @param maxResults The maximum number of results to return. Use
   *                   zero (0) to return all results.
   */
  public NamingEnumeration getUsers(String searchText, String field,
                                    int maxResults) 
    throws NamingException ;

  /**
   * Returns a <code>NamingEnumeration</code> containing
   * <code>SearchResult</code>s. You must close the NamingEnumeration
   * if you don't traverse the entire thing.
   *
   * @param filter A complete LDAP search filter.
   * @param maxResults The maximum number of results to return. Use
   *                   zero (0) to return all results.
   */
  public NamingEnumeration getUsers(String filter, int maxResults)
    throws NamingException ;

  /**
   * Returns a user's attributes. 
   *
   * @param uid The user's unique identifier
   */
  public Attributes        getUser(String uid) 
    throws NamingException ;

  /**
   * Modifies a user's attributes
   *
   * @param uid The user's unique identifier
   * @param mods The modifications to make to specific attributes
   */
  public void              editUser(String uid, ModificationItem[] mods) 
    throws NamingException ;

  /**
   * Adds the given user to the LDAP database. The parameter 
   * <code>attrs</code> must contain
   * all required attributes other than objectClass, but including
   * the uid.
   *
   * @param uid The user's unique identifier
   * @param attrs The user's LDAP attributes.
   */
  public void              addUser(String uid, Attributes attrs) 
    throws NamingException ;

  /**
   * Removes the given user from the LDAP database
   *
   * @param uid The user's unique identifier
   */
  public void              deleteUser(String uid) 
    throws NamingException ;

  /**
   * Returns a <code>NamingEnumeration</code> containing
   * <code>SearchResult</code>s. You must close the NamingEnumeration
   * if you don't traverse the entire thing.
   *
   * @param uid The user's unique identifier who is assigned to
   *            the roles you are searching for.
   */
  public NamingEnumeration getRoles(String uid) 
    throws NamingException ;

  /**
   * Returns a <code>NamingEnumeration</code> containing
   * <code>SearchResult</code>s. You must close the NamingEnumeration
   * if you don't traverse the entire thing.
   *
   * @param searchText The text to search for in the field
   * @param field The ldap attribute name to search in
   * @param maxResults The maximum number of results to return. Use
   *                   zero (0) to return all results.
   */
  public NamingEnumeration getRoles(String searchText, String field,
                                    int maxResults) 
    throws NamingException ;

  /**
   * Returns a <code>NamingEnumeration</code> containing
   * <code>SearchResult</code>s. You must close the NamingEnumeration
   * if you don't traverse the entire thing. This returns all
   * roles up to the maxResults.
   *
   * @param maxResults The maximum number of results to return. Use
   *                   zero (0) to return all results.
   */
  public NamingEnumeration getRoles(int maxResults) 
    throws NamingException ;

  /**
   * Returns a role's attributes.
   *
   * @param rid The role's unique identifier
   */
  public Attributes        getRole(String rid) 
    throws NamingException ;

  /**
   * Assigns a user to a role
   *
   * @param uid The user's unique identifier
   * @param rid The role's unique identifier
   */
  public void              assign(String uid, String rid) 
    throws NamingException ;

  /**
   * Unassigns a user from a role
   *
   * @param uid The user's unique identifier
   * @param rid The role's unique identifier
   */
  public void              unassign(String uid, String rid) 
    throws NamingException ;

  /**
   * Creates a role with the given unique identifier and all other attributes
   * empty.
   *
   * @param rid The role's unique identifier
   */
  public void              addRole(String rid) 
    throws NamingException ;

  /**
   * Creates a role with the given unique identifier and attributes as given
   * by attrs.
   *
   * @param rid The role's unique identifier
   * @param attrs The role's LDAP attributes
   */
  public void              addRole(String rid, Attributes attrs) 
    throws NamingException ;

  /**
   * Modifies a role's LDAP attributes.
   *
   * @param rid The role's unique identifier
   * @param mods The modifications to make to the role's attributes
   */
  public void              editRole(String rid, ModificationItem[] mods) 
    throws NamingException ;

  /**
   * Deletes a role from the LDAP database.
   *
   * @param rid The role's unique identifier
   */
  public void              deleteRole(String rid) 
    throws NamingException ;
}
