/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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
