/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA
).
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
 */

package org.cougaar.core.security.crypto;

  /*
   * This is a public class representing certain critical information about
   * a connection.  One funny thing about this class is that the sender and 
   * the receiver fill in different parts of this structure.  On the
   * sending side, the source and target are known but it is not easy
   * to determine determine the sourceNodePrincipal associated with
   * the connection.  So the sender will simply use null for the
   * source node principal.  On the receiving side, the receiver is
   * more concerned with the source agent and the source node for the
   * message.  If the receiver trusts the source agent, the source
   * node and the assertion that the agent is on the node then he will
   * trust the message (assuming ssl) and not require signatures.
   * 
   * I think that I can assume that the _source is never null.
   */
public class ConnectionInfo
{
  private String _source;
  private String _sourceNodePrincipal;
  private String _target;

  public ConnectionInfo(String source, 
                        String sourceNodePrincipal,
                        String target)
  {
    _source              = source;
    _sourceNodePrincipal = sourceNodePrincipal;
    _target              = target;
  }

  public boolean equals(Object o)
  {
    if (o instanceof ConnectionInfo) {
      ConnectionInfo ci = (ConnectionInfo) o;
      return 
        _source.equals(ci._source) &&
        compareStrings(_sourceNodePrincipal, ci._sourceNodePrincipal) &&
        compareStrings(_target, ci._target);
    } else { return false; }
  }

  public int hashCode()
  {
    return
      _source.hashCode() + 
      (_sourceNodePrincipal == null ? 42 : _sourceNodePrincipal.hashCode()) +
      (_target == null ? 42 : _target.hashCode());
  }

  public String toString()
  {
    return 
      _source + "/" + _sourceNodePrincipal + " -> "
      + (_target == null ? "me" : _target);
  }

  private boolean compareStrings(String x, String y)
  {
    if (x == null) {
      return y == null;
    } else if (y == null) {
      return false;
    } else {
      return x.equals(y);
    }
  }
}
