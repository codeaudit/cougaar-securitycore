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


package org.cougaar.core.security.services.identity;

import java.security.cert.Certificate;

import org.cougaar.core.component.Service;
import org.cougaar.core.service.identity.IdentityDeniedException;
import org.cougaar.core.service.identity.PendingRequestException;

public interface UserIdentityService
  extends Service
{
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
   * @exception  PendingRequestException the certificate authority
   *             did not sign the request immediately. The same request
   *             should be sent again later
   * @exception  IdentityDeniedException the certificiate authority
   *             refused to sign the key
   */
  public void CreateCryptographicIdentity(UserProfile profile)
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

