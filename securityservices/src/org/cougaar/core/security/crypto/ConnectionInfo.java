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
