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

import java.util.List;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.DataProtectionService;
import org.cougaar.core.security.services.util.PersistenceMgrPolicyService;
import org.cougaar.core.node.NodeControlService;

public final class DataProtectionComponent
  extends SecurityComponent
{
  protected BindingSite bindingSite = null;
  private LoggingService log;
  private String mySecurityCommunity;

  public DataProtectionComponent() {
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
    final ServiceBroker sb = bindingSite.getServiceBroker();
    // Get root service broker
    ServiceBroker rootServiceBroker = null;
    NodeControlService nodeControlService = (NodeControlService)
      sb.getService(this, NodeControlService.class, null);
    if (nodeControlService != null) {
      rootServiceBroker = nodeControlService.getRootServiceBroker();
      if (rootServiceBroker == null) {
        throw new RuntimeException("Unable to get root service broker");
      }
    }
    else {
      // We are running outside a Cougaar node.
      // No Cougaar services are available.
      rootServiceBroker = sb;
    }

    PersistenceMgrPolicyServiceProvider cmsp = new PersistenceMgrPolicyServiceProvider(sb, mySecurityCommunity);
    rootServiceBroker.addService(PersistenceMgrPolicyService.class, cmsp);
    if (log.isDebugEnabled()) {
    	log.debug("PersistencePolicyManagerService started");
    }
    boolean dataOn =
    	Boolean.valueOf(System.getProperty("org.cougaar.core.security.dataprotection", "true")).booleanValue();
    if (dataOn) {
      DataProtectionServiceProvider ssp = new DataProtectionServiceProvider(sb, mySecurityCommunity);
	    if (log.isDebugEnabled()) {
	    	log.debug("DataProtectionService started");
	    }
      rootServiceBroker.addService(DataProtectionService.class, ssp);
    }
  }

  public void setState(Object loadState) {}
  public Object getState() {return null;}

  public synchronized void unload() {
    super.unload();
    // unload services in reverse order of "load()"
    ServiceBroker sb = bindingSite.getServiceBroker();
    // release services
  }
}
