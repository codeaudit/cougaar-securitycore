/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.crypto;

import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.lang.ClassNotFoundException;
import java.security.GeneralSecurityException;
import java.text.MessageFormat;
import java.text.ParseException;

// Cougaar core services
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

public class BasicMessageInputStream
  extends ProtectedInputStream
{
  /** ProtectedOutputStream can read old attributes (check to see if it should
   *  write the signature. Note at this point the attributes were already sent)
   */
  private InputStream inputStream;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  
  public BasicMessageInputStream(InputStream stream,
				 MessageAddress source,
				 MessageAddress target,
				 ServiceBroker sb) {
    super(stream);
    serviceBroker = sb;

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    inputStream = stream;
  }
  /* ************************************************************************
   * FilterInputStream implementation
   */
  public int read()
    throws IOException {
    return inputStream.read();
  }

  public int read(byte[] b)
    throws IOException {
    return inputStream.read(b);
  }

  public int read(byte[] b, int off, int len)
    throws IOException {
    return inputStream.read(b, off, len);
  }

  public long skip(long n)
    throws IOException {
    return inputStream.skip(n);
  }

  public int available()
    throws IOException {
    return inputStream.available();
  }

  public void close()
    throws IOException {
    inputStream.close();
  }

  public void mark(int readlimit) {
    inputStream.mark(readlimit);
  }

  public void reset()
    throws IOException {
    inputStream.reset();
  }

  public boolean markSupported() {
    return inputStream.markSupported();
  }


  /* ***********************************************************************
   * ProtectedInputStream implementation
   */
  public void finishInput(MessageAttributes attributes)
    throws java.io.IOException {
  }

  /* ***********************************************************************
   * Private methods
   */
}
