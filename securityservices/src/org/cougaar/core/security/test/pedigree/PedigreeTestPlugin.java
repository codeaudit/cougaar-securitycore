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


package org.cougaar.core.security.test.pedigree;

import org.cougaar.core.security.services.auth.PedigreeService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;

public class PedigreeTestPlugin
  extends org.cougaar.core.plugin.ComponentPlugin
{
  private PedigreeService             pedigreeService;
  private AgentIdentificationService  aiService;
  private LoggingService              log;
  
  protected void setupSubscriptions()
  {
    log = (LoggingService)
    getBindingSite().getServiceBroker().getService(
        this,
        LoggingService.class,
        null);
    if (log.isDebugEnabled()) {
      log.debug("PedigreeTestPlugin.setupSubscriptions - " + getBindingSite().getServiceBroker());
    }
    
    // Get agent mobility service
    aiService = (AgentIdentificationService)
    getBindingSite().getServiceBroker().getService(
        this, 
        AgentIdentificationService.class,
        null);

    pedigreeService = (PedigreeService)
    getBindingSite().getServiceBroker().getService(
        this,
        PedigreeService.class,
        null);
    
    if (log.isDebugEnabled()) {
      log.debug("PedigreeTestPlugin. Agent name: " + aiService.getName());
    }
    pedigreeService.getPedigree(this);
  }
  
  
  protected void execute()
  {
  }
}
