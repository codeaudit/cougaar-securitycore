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

import java.util.Random;

import org.cougaar.core.mts.Message;
import org.cougaar.core.mts.MessageAddress;

public final class StopSigningMessage extends Message 
{
  private static Random _r = new Random();
  private MessageAddress _sender;
  private MessageAddress _receiver;
  private int _id;

  // This message is a response to a signed message, X, from sender to
  // receiver. myNode is the node on which the message, X, has been
  // received.  This message is sent from myNode back to the sender of
  // X.
  public StopSigningMessage(MessageAddress myNode,
                            MessageAddress sender, 
                            MessageAddress receiver,
                            boolean        debugFlag)
  {
    // Send the message from my node to the sender of the message that 
    // doesn't need signing
    super(myNode, sender);
    _sender   = sender;
    _receiver = receiver;
    if (debugFlag) {
      _id       = _r.nextInt();
    }
  }

  public MessageAddress getSender()
  {
    return _sender;
  }

  public MessageAddress getReceiver()
  {
    return _receiver;
  }

  public String toString()
  {
    return "<StopSigningMessage " + _sender + " --> " + _receiver +
      " (" + _id + ")";
  }
}
