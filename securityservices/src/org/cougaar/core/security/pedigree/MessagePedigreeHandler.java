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

package org.cougaar.core.security.pedigree;

import org.cougaar.core.mts.Message;
import org.cougaar.core.security.services.auth.Pedigree;
import org.cougaar.mts.std.AttributedMessage;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


public class MessagePedigreeHandler {
  /**
   * A ThreadLocal variable to store the pedigree of a message between
   * the following two states:
   *  a) A LogicProvider is invoked by the Blackboard to process an incoming
   *     message.
   *  b) The LogicProvider publishes objects on the blackboard as a result
   *     of receiving the incoming message. 
   */
  private static ThreadLocal myThreadLocal;
  /**
   * The singleton instance of this class.
   */
  private static MessagePedigreeHandler theInstance;
  private static PedigreePermission     pedigreePermission;
  private static Logger                 _log;
  
  static {
    _log = LoggerFactory.getInstance().createLogger(MessagePedigreeHandler.class);
    theInstance = new MessagePedigreeHandler();
    pedigreePermission = new PedigreePermission("getPedigreeHandler");
  }
  
  private MessagePedigreeHandler() {
  }
  
  /**
   * Obtains the MessagePedigreeHandler singleton.
   * Only privileged components can obtain this handler.
   * @return the singleton instance of the MessagePedigreeHandler
   */
  public static MessagePedigreeHandler getInstance() {
    if (System.getSecurityManager() != null) {
      System.getSecurityManager().checkPermission(pedigreePermission);
    }
    return theInstance;
  }
  
  public void setThreadLocalPedigree(Message m) {
    // TODO: MessagesAttributes could be used to obtain additional security attributes
    // such as X.509 certificate used to encrypt message.
    Pedigree p = getPedigree(m);
    if (_log.isDebugEnabled()) {
      _log.debug("Setting pedigree: " + p);
    }
    myThreadLocal = new ThreadLocal();
    myThreadLocal.set(p);
  }
  
  /**
   * Removes the ThreadLocal variable from the thread.
   *
   */
  public void resetThreadLocalPedigree() {
    myThreadLocal = null;
  }
  
  /**
   * 
   * @return the pedigree stored in a ThreadLocal variable.
   */
  public Pedigree getThreadLocalPedigree() {
    Pedigree p = null;
    if (myThreadLocal != null) {
      p = (Pedigree)myThreadLocal.get();
    }
    return p;
  }

  /**
   * Constructs the Pedigree of a message.
   * @param m - The message for which a Pedigree object should be constructed.
   * @return - The Pedigree of the message.
   */
  private Pedigree getPedigree(Message m) {
    return new Pedigree(m.getOriginator());
  }
  
}