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

package org.cougaar.core.security.services.identity;

import java.security.cert.Certificate;
import org.cougaar.core.component.Service;

public interface UserIdentityService extends Service {
  /** Create a cryptographic identity for an user.
   *  This method is called by restricted entities which act
   *  as CA registry. The CA registry will interact with user
   *  to obtain a user profile (i.e. through html form), then
   *  submit the user information to the CA. The registry
   *  entity is responsible for authenticating the user, generating
   *  the certificate request, and providing retrieving method
   *  so that user can retrieve the certificate.
   *
   *  If the user already has a cryptographic identity, the
   *  method returns immediately. If the user does not have
   *  a cryptographic key, or if no key is valid, a new key
   *  is created.
   *
   *  This service provider will call checkPermission() to
   *  make sure that only known entities will call the service.
   *
   * @param      profile of the user
   * @param      clientCallBack a callBack to the client
   * @exception  PendingRequestException the certificate authority
   *             did not sign the request immediately. The same request
   *             should be sent again later
   * @exception  IdentityDeniedException the certificiate authority
   *             refused to sign the key
   */
  public void CreateCryptographicIdentity(UserProfile profile,
					  RevocationCallBack clientCallBack)
    throws PendingRequestException,
	   IdentityDeniedException;


  /**
   */
  public void RevokeCryptographicIdentity(UserProfile profile);

  /**
   * Check certificate validity - check if certificate is not yet valid,
   *               is expired, is revoked, is not trusted (selfsigned), etc.
   *
   * Should this be provided in another api?
   */
  public boolean checkCryptographicIdentity(Certificate cert);

  /**
   * User management
   * The information on user profile will be stored in centralized
   * data storage (database or LDAP). And the user information
   * (password, role) may be modified.
   *
   * The authentication and authorization of the user is checked by
   * the component that uses this API.
   *
   * Allow to modify username? Username is used as the unique entity.
   * @exception   InvalidProfileException the user profile has
   *              incorrect username, or modified field is immutable.
   *              Also for changing to a role that is not permitted.
   */

  public void modifyUserProfile(UserProfile profile)
    throws InvalidProfileException;

  /**
   */
  public void addUser(UserProfile profile);

  /**
   * @return      null if username not found. This can be used
   *              to check whether add is successful.
   */
  public UserProfile getUserProfile(String username);

  /**
   * The certificates associate with the user profile needs to
   * be revoked as well.
   */
  public void removeUser(UserProfile profile);

}

