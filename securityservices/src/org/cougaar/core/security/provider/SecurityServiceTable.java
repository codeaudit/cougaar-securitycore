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

import java.util.Hashtable;

import org.cougaar.core.service.LoggingService;

public class SecurityServiceTable
  extends Hashtable
{
  private LoggingService log;
  private static SecurityServiceTable securityServiceTable;

  private SecurityServiceTable(LoggingService aLog) {
    log = aLog;
  }

  public Object put(Object service, Object provider) {
    if (log.isDebugEnabled()) {
     log.debug("Adding service " + ((Class)service).getName());
    }
    if (!(provider instanceof BaseSecurityServiceProvider)) {
      String msg = "Provider is not a BaseSecurityServiceProvider: " + ((Class)provider).getName();
      log.error(msg);
      throw new RuntimeException(msg);
    }
    else {
      return super.put(service, provider);
    }
  }

  public static synchronized SecurityServiceTable getInstance(LoggingService aLog) {
    if (securityServiceTable == null) {
      securityServiceTable = new SecurityServiceTable(aLog);
    }
    return securityServiceTable;
  }
}
