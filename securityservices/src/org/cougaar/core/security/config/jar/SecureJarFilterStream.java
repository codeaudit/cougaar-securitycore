/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
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
