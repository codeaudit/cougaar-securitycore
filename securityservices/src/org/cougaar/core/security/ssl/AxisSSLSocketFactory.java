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

package org.cougaar.core.security.ssl;

import org.apache.axis.components.net.JSSESocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.util.Hashtable;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

/**
 * SSL socket factory for Axis.
 */
public class AxisSSLSocketFactory extends JSSESocketFactory
{
    protected static Logger log =
       LoggerFactory.getInstance().createLogger(AxisSSLSocketFactory.class);

    private static SSLSocketFactory mySslSocketFactory;

    /**
     * Constructor AxisSSLSocketFactory
     *
     * @param attributes
     */
    public AxisSSLSocketFactory(Hashtable attributes) {
        super(attributes);
    }

    /**
     * Initialize the SSLSocketFactory
     * @throws IOException
     */ 
    protected void initFactory() throws IOException {
        if (log.isDebugEnabled()) {
          log.debug("initFactory - " + mySslSocketFactory);
        }
        if (mySslSocketFactory == null) {
          throw new IllegalStateException("SSLSocketFactory has not been set yet");
        }
        sslFactory = mySslSocketFactory;
    }

    public static void setSSLSocketFactory(SSLSocketFactory sslSocketFactory) {
        if (log.isDebugEnabled()) {
          log.debug("setSSLSocketFactory - " + sslSocketFactory);
        }
      if (mySslSocketFactory != null) {
        throw new IllegalStateException("SSLSocketFactory has already been set");
      }
      mySslSocketFactory = sslSocketFactory;
    }
}

