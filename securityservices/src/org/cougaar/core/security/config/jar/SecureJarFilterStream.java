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


package org.cougaar.core.security.config.jar;

import java.io.FilterInputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class SecureJarFilterStream
  extends FilterInputStream
{
  URL _url = null;
  private static final Logger _logger =
    LoggerFactory.getInstance().createLogger(SecureJarFilterStream.class);

  private static long m_totalTime;

  SecureJarFilterStream(URL u) 
    throws GeneralSecurityException, IOException {
    super(new BufferedInputStream(u.openStream()));
    _url = u;
    init();
  }

  SecureJarFilterStream(InputStream in) 
    throws GeneralSecurityException, IOException {
    super(new BufferedInputStream(in));
    init();
  }

  private void init() throws GeneralSecurityException, IOException {
    // Unfortunately, we don't know that the signature is
    // correct until we have read the whole stream.
    // So, we read the stream until the end, and we see if we
    // get any exception.
    long a = 0;
    if (_logger.isInfoEnabled()) {
      a = System.currentTimeMillis();
    }
    byte buffer[] = new byte[1000];
    try {
      while (in.read(buffer, 0, buffer.length) != -1);
    }
    catch (Exception e) {
      String message = "Invalid JAR file";
      if (_url != null) {
        message += ": " + _url;
      }
      GeneralSecurityException gse =
	new GeneralSecurityException(message);
      gse.initCause(e);
      throw gse;
    }
    if (_logger.isInfoEnabled()) {
      long b = System.currentTimeMillis();
      m_totalTime += (b - a);
      _logger.info("Time spent: " + (b - a ) + " Total: " + m_totalTime);
    }
  }
}
