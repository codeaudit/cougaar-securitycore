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


package org.cougaar.core.security.provider;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

import javax.net.ssl.SSLSocketFactory;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.node.NodeControlService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.crypto.SSLService;
import org.cougaar.core.security.services.identity.WebserverIdentityService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.ssl.JaasSSLFactory;
import org.cougaar.core.service.LoggingService;

public final class SSLServiceComponent
  extends SecurityComponent
{
  protected BindingSite bindingSite = null;
  private LoggingService log;
  private String mySecurityCommunity;
  private ServiceBroker serviceBroker;
  private ServiceBroker rootServiceBroker;
  private KeyRingService krs;
  
  // Service Providers (needed to stop the component).
  private ServiceProvider webServerSP;
  private ServiceProvider sslSP;
  private SSLService sslService;
  private SSLSocketFactory oldSSLSocketFactory;
  private WebserverIdentityService webServerService;

  public SSLServiceComponent() {
  }

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() != 1) {
      throw new IllegalArgumentException(this.getClass().getName()
					 + " should take 1 parameter, got " + l.size()
					 + ". Fix configuration file");
    }
    else {
      mySecurityCommunity = l.get(0).toString();
    }
  }

  private void setLoggingService() {
    if (log == null) {
      ServiceBroker sb = bindingSite.getServiceBroker();
      log = (LoggingService)
	sb.getService(this,
		      LoggingService.class, null);
    }
  }

  public void setBindingSite(BindingSite bs) {
    bindingSite = bs;
  }

  public void load() {
    super.load();
    setLoggingService();
    serviceBroker = bindingSite.getServiceBroker();

    if (log.isDebugEnabled()) {
      log.debug("SSL Compoent started.");
    }

    // Get root service broker
    NodeControlService nodeControlService = (NodeControlService)
      serviceBroker.getService(this, NodeControlService.class, null);
    if (nodeControlService != null) {
      rootServiceBroker = nodeControlService.getRootServiceBroker();
      serviceBroker.releaseService(this, NodeControlService.class, nodeControlService);
      nodeControlService = null;
      if (rootServiceBroker == null) {
        throw new RuntimeException("Unable to get root service broker");
      }
    }
    else {
      // We are running outside a Cougaar node.
      // No Cougaar services are available.
      rootServiceBroker = serviceBroker;
    }

    krs = (KeyRingService) rootServiceBroker.getService(this,
                                                      KeyRingService.class,
                                                      null);

    if (krs == null) {
      addServiceAvailableListener();
    }
    else {
      registerServices();
    }
  }     

  private void addServiceAvailableListener() {
    serviceBroker.addServiceListener(new ServiceAvailableListener() {
      public void serviceAvailable(ServiceAvailableEvent ae) {
        Class sc = ae.getService();
        if (sc == KeyRingService.class && krs == null) {
          krs = (KeyRingService)
            serviceBroker.getService(this, KeyRingService.class, null);
          if (krs != null) {
            registerServices();
          } 
        }
      }
    });
  }

  private void registerServices() {
    if (log.isDebugEnabled()) {
      log.debug("register SSL services");
    }

    /* ********************************
     * SSL services
     */
    SecurityPropertiesService secprop = (SecurityPropertiesService)
          rootServiceBroker.getService(this, SecurityPropertiesService.class, null);

      sslSP = new SSLServiceProvider(serviceBroker, mySecurityCommunity);
      //services.put(SSLService.class, sslSP);
      rootServiceBroker.addService(SSLService.class, sslSP);

      // SSLService and WebserverIdentityService are self started
      // they offer static functions to get socket factory
      // in the functions the permission will be checked.
      sslService = (SSLService)rootServiceBroker.getService(this, SSLService.class, null);

      JaasSSLFactory jaasSSLFactory = new JaasSSLFactory(krs, rootServiceBroker);
      
      // Remember old SSL Socket Factory, useful to stop this component and revert
      // back to the original.
      oldSSLSocketFactory = javax.net.ssl.HttpsURLConnection.getDefaultSSLSocketFactory();
      javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(jaasSSLFactory);

      // Axis SSL socket factory (web services)
      try {
        Class c = Class.forName("org.cougaar.core.security.ssl.AxisSSLSocketFactory");
        Class paramTypes[] = {SSLSocketFactory.class};
        Method m = c.getMethod("setSSLSocketFactory", paramTypes);
        Object paramValues[] = {jaasSSLFactory};
        m.invoke(null, paramValues);
      }
      catch (NoClassDefFoundError e) {
        // Don't load the AXIS component. That's ok if AXIS is not enabled.
        if (log.isInfoEnabled()) {
          log.info("AxisSSLSocketFactory not enabled");
        }
      }
      catch (ClassNotFoundException e) {
        // Don't load the AXIS component. That's ok if AXIS is not enabled.
        if (log.isInfoEnabled()) {
          log.info("AxisSSLSocketFactory not enabled");
        }
      } catch (SecurityException e) {
        // getMethod Exception
        if (log.isErrorEnabled()) {
          log.error("Unable to access AxisSSLSocketFactory.setSSLSocketFactory method", e);
        }
      } catch (NoSuchMethodException e) {
        // getMethod Exception
        if (log.isErrorEnabled()) {
          log.error("AxisSSLSocketFactory.setSSLSocketFactory method does not exist", e);
        }
      } catch (IllegalArgumentException e) {
        // Method.invoke exception
        if (log.isErrorEnabled()) {
          log.error("Unable to set AxisSSLSocketFactory.setSSLSocketFactory", e);
        }
      } catch (IllegalAccessException e) {
        // Method.invoke exception
        if (log.isErrorEnabled()) {
          log.error("Unable to set AxisSSLSocketFactory.setSSLSocketFactory", e);
        }
      } catch (InvocationTargetException e) {
        // Method.invoke exception
        if (log.isErrorEnabled()) {
          log.error("Unable to set AxisSSLSocketFactory.setSSLSocketFactory", e);
        }
      }

      krs.finishInitialization();

      // configured to use SSL?
      if (secprop.getProperty(SecurityPropertiesService.WEBSERVER_HTTPS_PORT, null) != null) {
        webServerSP = new WebserverSSLServiceProvider(serviceBroker, mySecurityCommunity);
        //services.put(WebserverIdentityService.class, webServerSP);
        rootServiceBroker.addService(WebserverIdentityService.class, webServerSP);
        webServerService = (WebserverIdentityService)
          rootServiceBroker.getService(this, WebserverIdentityService.class, null);
      }
      rootServiceBroker.releaseService(this, SecurityPropertiesService.class, secprop);
      secprop = null;
  }

  public void setState(Object loadState) {}
  public Object getState() {return null;}

  public synchronized void stop() {
    // unload services in reverse order of "load()"
    ServiceBroker sb = bindingSite.getServiceBroker();
    
    // Release WebserverIdentityService
    rootServiceBroker.releaseService(this, WebserverIdentityService.class, webServerService);
    
    // Revoke WebserverIdentityService
    rootServiceBroker.revokeService(WebserverIdentityService.class, webServerSP);
    webServerSP = null;
    
    // Set SSL Socket Factory back to original.
    javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(oldSSLSocketFactory);
    
    // Release SSL service
    rootServiceBroker.releaseService(this, SSLService.class, sslService);
    sslService = null;
    
    // Revoke SSL services
    if (sslSP != null) {
      rootServiceBroker.revokeService(SSLService.class, sslSP);
      sslSP = null;
    }
    
    // Release KeyRing service
    if (krs != null) {
      rootServiceBroker.releaseService(this, KeyRingService.class, krs);
      krs = null;
    }
    
    // Release logging service.
    if (log != null) {
      sb.releaseService(this, LoggingService.class, log);
      log = null;
    }
    super.stop();
  }
}
