/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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

package org.cougaar.security.mop.ethereal;

public class ProtocolPolicy
{
  /** The name of the protocol.
   */
  private String _protocolName;

  /** Indicate whether the protocol is protected through cryptographic means.
   *  null means it is unknown.
   */
  private Boolean _isEncrypted;

  /** Indicate whether it's ok to see this protocol on the network.
   *  null means it is unknown.
   */
  private Boolean _isOk;

  public ProtocolPolicy(String name, Boolean encrypted, Boolean ok) {
    _protocolName = name;
    _isEncrypted = encrypted;
    _isOk = ok;
  }
  public String getProtocolName() { return _protocolName; }
  public Boolean isEncrypted() { return _isEncrypted; }
  public Boolean isOk() { return _isOk; }
}
