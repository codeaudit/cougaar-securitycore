
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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.ServiceProvider;
import org.cougaar.core.security.provider.SecurityComponent;
import org.cougaar.core.security.services.auth.PedigreeService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


public final class PedigreeComponentFactory
  extends SecurityComponent
{
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger(PedigreeComponentFactory.class);
  }
  
  public PedigreeComponentFactory() {
  }

  public void load() {
    super.load();
    if (_log.isDebugEnabled()) {
      _log.debug("Loading " + getClass().getName());
    }
    final ServiceBroker sb = bindingSite.getServiceBroker();

    /* ********************************
     * Add Pedigree service to ServiceBroker of agent
     */
    ServiceProvider newSP = new PedigreeServiceProvider(sb, mySecurityCommunity);
    sb.addService(PedigreeService.class, newSP);
  }
}
