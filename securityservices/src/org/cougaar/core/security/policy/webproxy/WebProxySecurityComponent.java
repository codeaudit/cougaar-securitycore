package org.cougaar.core.security.policy.webproxy;

import org.cougaar.core.security.policy.webproxy.WebProxyInstaller;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.Component;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.GenericStateModelAdapter;

public final class WebProxySecurityComponent
  extends GenericStateModelAdapter
  implements Component
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
  public void WebProxySecurityComponent()
  {
    proxyInstaller = new WebProxyInstaller();
    proxyInstaller.install();
  }

  public void setBindingSite(BindingSite bs) {
    bindingSite = bs;
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
