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

package com.nai.security.policy;

import sun.security.x509.*;
import java.net.*;

/** This class contains the default attributes used to generate
 *  a certificate
 */
public class CertificateAttributesPolicy {

  /** The default Organization Unit when generating a new certificate
   */
  public String ou;

  /** The default Organization when generating a new certificate
   */
  public String o;

  /** The default locality when generating a new certificate
   */
  public String l;

  /** The default State when generating a new certificate
   */
  public String st;

  /** The default country name when generating a new certificate
   */
  public String c;

  /** The default domain when generating a new certificate
   */
  public String domain;

  /** The algorithm used to generate the key
   */
  public String keyAlgName;

  /** The key size
   */
  public int keysize;

  /** The default period of validity
   */
  public long howLong;

  /** The signature algorithm name
   */
  public String sigAlgName;

  /** Determines whether the node key is used to sign other keys in the node
   */
  public boolean nodeIsSigner;

  public String toString() {
    return "ou=" + ou + " - o=" + o + " - l=" + l + " - st=" + st
      + " - c=" + c + " - domain=" + domain
      + " - keysize=" + keysize
      + " - howLong=" + howLong
      + " - sigAlgName=" + sigAlgName
      + " - keyAlgName=" + keyAlgName;
  }
};
