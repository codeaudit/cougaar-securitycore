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

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.OutputStream;

public class BasicMessageOutputStream
  extends ProtectedOutputStream
{
  /** ProtectedOutputStream can read old attributes (check to see if it should
   *  write the signature. Note at this point the attributes were already sent)
   */
  private OutputStream outputStream;
  private ServiceBroker serviceBroker;
  private LoggingService log;
  
  public BasicMessageOutputStream(OutputStream stream,
				  MessageAddress source,
				  MessageAddress target,
				  ServiceBroker sb) {
    super(stream);
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    outputStream = stream;
  }
  
  /* ***********************************************************************
   * FilterOutputStream implementation
   */

  public void write(byte[] b)
    throws IOException {
    outputStream.write(b);
  }

  public void write(byte[] b, int off, int len)
    throws IOException {
    outputStream.write(b, off, len);
  }

  public void write(int b)
    throws IOException {
    outputStream.write(b);
  }

  public void flush()
    throws IOException {
    outputStream.flush();
  }

  public void close()
    throws IOException {
    outputStream.close();
  }

  /* **********************************************************************
   * ProtectedOutputStream implementation
   */

  public void finishOutput(MessageAttributes attributes)
    throws java.io.IOException {
  }

  /* ***********************************************************************
   * Private methods
   */
}
