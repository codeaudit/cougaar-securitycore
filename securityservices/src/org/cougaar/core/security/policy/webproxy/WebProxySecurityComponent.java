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


package org.cougaar.core.security.policy.webproxy;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ComponentSupport;
import org.cougaar.core.component.ServiceBroker;

public final class WebProxySecurityComponent
  extends ComponentSupport //GenericStateModelAdapter
//   implements Component
{
  private WebProxyInstaller proxyInstaller;
  protected BindingSite bindingSite = null;


  /**
   * The one and only purpose of this code is to install the web proxy
   * before the tomcat engine starts running.  
   *
   * This code and tomcat both install a URLStreamHandlerFactory.  If
   * the tomcat engine starts first, this attempt to start the factory
   * fails.  If we start first, we install the tomcat factory protocol
   * (jndi) as tomcat would have and tomcat politely does not signal
   * an error.  
   */
  public WebProxySecurityComponent()
  {
    proxyInstaller = new WebProxyInstaller();
    proxyInstaller.install();
  }

  public void setBindingSite(BindingSite bs) {
    bindingSite = bs;
  }

  public void setParameter(Object o) {
  }

  /**
   * When the service broker becomes available, my code can start
   * loggging.
   */
  public void load() {
    super.load();
    ServiceBroker sb = bindingSite.getServiceBroker();
    proxyInstaller.installServiceBroker(sb);
  }

  public void setState(Object loadState) {}
  public Object getState() {return null;}

  /*
   * Should fill this in sometime.  It is not clear that this can be unloaded
   * but at the very least the proxy could be disabled (using a flag
   * in DamlURLStreamHandler.
   */
  public synchronized void unload() {
    super.unload();
  }

  
}
