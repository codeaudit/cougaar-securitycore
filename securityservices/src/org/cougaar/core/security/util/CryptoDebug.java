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


package org.cougaar.core.security.util;

// Cougaar security services
import org.cougaar.core.security.services.util.SecurityPropertiesService;

public  class CryptoDebug {
  public static boolean debug =false;
  public static boolean crldebug =false;

  private static SecurityPropertiesService secprop = null;

  static {
    debug =
      (Boolean.valueOf(System.getProperty(SecurityPropertiesService.CRYPTO_DEBUG,
					   "false"))).booleanValue();
    crldebug =
      (Boolean.valueOf(System.getProperty(SecurityPropertiesService.CRYPTO_CRL_DEBUG,
					   "false"))).booleanValue();
  }

  public static void initContext(javax.servlet.Servlet servlet) {
    // TODO. Modify following line to use service broker instead
    secprop = new SecurityPropertiesServiceImpl(null);

    debug =
      (Boolean.valueOf(secprop.getProperty(SecurityPropertiesService.CRYPTO_DEBUG,
					   "false"))).booleanValue();
    crldebug =
      (Boolean.valueOf(secprop.getProperty(SecurityPropertiesService.CRYPTO_CRL_DEBUG,
					   "false"))).booleanValue();
  }
} 
