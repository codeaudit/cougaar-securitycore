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

package org.cougaar.core.service;

import java.io.Serializable;
import javax.crypto.SealedObject;
import java.io.InputStream;
import java.io.OutputStream;

// Cougaar core services
import org.cougaar.core.component.Service;
import org.cougaar.core.security.coreservices.crypto.EncryptAttributes;

public interface DataProtectionService extends Service {

  /** Encrypt a data stream, attribTag is used to specify the
   *  policy driven attributes (encryption type, key strength, etc) to
   *  retrieve (or produce) the secret key used to encrypt the
   *  stream.
   *  @param  agentName   name of the agent which requests the service
   *  @param  encryptAttr The encryption information tagged as attributes.
   *                        i.e. blackboard, trust attribute, ...
   *  @param  out         Stream to be written for output.
   *  @param  in          Stream to be encrypted
   */
  public void encryptStream(String agentName,
                            EncryptAttributes encryptAttr,
                            OutputStream out,
                            InputStream in)
    throws RuntimeException,
            java.io.IOException;

  /** Issues/Comments: putting attributes on a string may be
   *  a bit of an overkill
   *  @param  agentName   name of the agent which requests the service
   *  @param  encryptAttr The encryption information tagged as attributes.
   *                        i.e. blackboard, trust attribute, ...
   *  @param  plainString the string to be encrypted
   *  @return the encrypted string
   */
  public String encryptString(String agentName,
                            EncryptAttributes encryptAttr,
                            String plainString)
    throws RuntimeException;

  /**
   *  @param  agentName   name of the agent which requests the service
   *  @param  encryptAttr The encryption information tagged as attributes.
   *                        i.e. blackboard, trust attribute, ...
   *  @param  inputObject the object to be encrypted
   *  @return encrypted object
   */
  public SealedObject encryptObject(String agentName,
                            EncryptAttributes encryptAttr,
                            Serializable inputObject)
    throws RuntimeException;

  /** For security reason, files are decrypted directly into
   * memory instead of a temporary file for storage, therefore
   * the file size should not be too large, ie, 1M.
   * For places where BufferedReader is used, instead use
   * ByteArrayOutputStream, convert output to string, then
   * use Stream reader to read the decrypted data.
   */

  /**
   *  @param  agentName   name of the agent which requests the service
   *  @param  encryptAttr The encryption information tagged as attributes.
   *                        i.e. blackboard, trust attribute, ...
   *  @param  in          the stream to be decrypted
   *  @param  out         the stream to be written
   */
  public void decryptStream(String agentName,
                            EncryptAttributes encryptAttr,
                            OutputStream out,
                            InputStream in)
    throws RuntimeException,
            java.io.IOException;

  /**
   *  @param  agentName   name of the agent which requests the service
   *  @param  encryptAttr The encryption information tagged as attributes.
   *                        i.e. blackboard, trust attribute, ...
   *  @param  encryptedString
   *                      The string to be decrypted
   *  @return the decrypted string
   */
  public String decryptString(String agentName,
                            EncryptAttributes encryptAttr,
                            String encryptedString)
    throws RuntimeException;

  /**
   *  @param  agentName   name of the agent which requests the service
   *  @param  encryptAttr The encryption information tagged as attributes.
   *                        i.e. blackboard, trust attribute, ...
   *  @param  encryptedObj
   *                      The object to be decrypted
   *  @return the decrypted object
   */
  public Object decryptObject(String agentName,
                            EncryptAttributes encryptAttr,
                            SealedObject encryptedObj)
    throws RuntimeException;

}
