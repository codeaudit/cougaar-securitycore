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


package org.cougaar.core.security.userauth;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.util.WeakHashMap;

public final class UserPasswordAuthenticator extends Authenticator
  implements AuthenticationListener {
  private PasswordAuthentication _pa = null;
  private AuthenticationHandler handler;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public UserPasswordAuthenticator(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    Authenticator.setDefault(this);
  }

  public void setAuthHandler(AuthenticationHandler handler) {
    this.handler = handler;
    handler.setAuthListener(this);
  }

  /**
   * return this for any criteria
   */
  public void setPasswordAuthentication(PasswordAuthentication pa) {
    _pa = pa;
  }

  /**
   * return this base on selected criteria
   */
  /*
  public void setPasswordAuthentication(
    String host, String port, String protocol, String username, char [] password) {
  }
  */

  /**
   * prompt user on selected criteria, if prompt is null use the prompt from the site
   */
  /*
  public void setPasswordAuthentication(
    String host, String port, String protocol, String prompt) {
  }
  */

  /**
   * The tidList contains a list of threads which have already tried using
   * the cached password. The problem is that the getPasswordAuthentication
   * function is not called simultaneously by the different threads so it
   * difficult to tell the difference between "bad password" or "no password"
   * response. Thus, this hack. Fortunately, I think we can count on Java
   * reusing a thread for a second try at accessing a URL and thus this hack
   * should be stable.
   *
   * Using a WeakHashMap because I don't want to keep around references to dead
   * threads. Since there is no WeakHashSet, I'll just use a dummy value for the
   * value.
   */
  private WeakHashMap tidList = new WeakHashMap();
  private static final String DUMMY_VALUE = "DUMMY";

  public PasswordAuthentication getPasswordAuthentication() {
    if (handler != null) {
      synchronized (tidList) {
        if (handler instanceof BasicAuthHandler) {
          Thread thread = Thread.currentThread();
          if (_pa != null && (!tidList.containsKey(thread))) {
          // this thread hasn't tried the cached password, yet
	    tidList.put(thread, DUMMY_VALUE);
	    return _pa; 
	  }
	  // getting a new password, clear the list
	  tidList.clear();
	  tidList.put(thread, DUMMY_VALUE);
        }
        try {
          String url = getRequestingProtocol() + "://" + getRequestingHost()
            + ":" + getRequestingPort() + "/";

          handler.setRequestingURL(url);
          handler.authenticateUser(handler.getUserName());
	  return _pa;
        } catch (Exception ex) {
	  if (log.isWarnEnabled()) {
	    log.warn("Unable to get requesting protocol", ex);
	  }
        }
      }
    }

    // should have a table of password authentication based on
    // host, port, protocol, etc
    return null;
  }
}
