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
 
 
 
 
 
 


package org.cougaar.core.security.auth;

import org.cougaar.core.security.services.auth.AuthorizationService;
import org.cougaar.core.security.services.auth.SecurityContextService;

import java.security.Permission;

public class ObjectContextUtil {
  private static SecurityContextService _scs;
  private static AuthorizationService   _auth;

  public static Permission SET_CONTEXT_PERMISSION = 
    new ContextPermission("setContextService");
  public static Permission SET_AUTH_PERMISSION = 
    new ContextPermission("setAuthorizationService");

  public static void setContextService(SecurityContextService scs) {
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
      sm.checkPermission(SET_CONTEXT_PERMISSION);
    }
    _scs = scs;
  }

  public static void setAuthorizationService(AuthorizationService auth) {
    SecurityManager sm = System.getSecurityManager();
    if (sm != null) {
      sm.checkPermission(SET_AUTH_PERMISSION);
    }
    _auth = auth;
  }
  
  public static ObjectContext createContext(Object obj) {
    if (_scs == null || _auth == null) {
      return null;
    }
    ExecutionContext ctx = _scs.getExecutionContext();
    if (ctx == null) {
      return null;
    }
    return _auth.createObjectContext(ctx, obj);
  }
}
