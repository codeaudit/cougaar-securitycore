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

import java.io.OutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;

// Cougaar core services
import org.cougaar.core.mts.ProtectedOutputStream;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.crypto.ProtectedObject;

public class MessageOutputStream
  extends ProtectedOutputStream
{
  /** ProtectedOutputStream can read old attributes (check to see if it should
   *  write the signature. Note at this point the attributes were already sent)
   */
  private OutputStream outputStream;
  private ByteArrayOutputStream dataOut;
  private boolean isEndOfMessage;
  private EncryptionService enc;
  private CryptoPolicyService cps;
  private MessageAddress source;
  private MessageAddress target;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  private static final int DEFAULT_INIT_BUFFER_SIZE = 200;

  public MessageOutputStream(OutputStream stream,
			     EncryptionService enc,
			     CryptoPolicyService cps,
			     MessageAddress source,
			     MessageAddress target,
			     ServiceBroker sb) {
    super(stream);
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    outputStream = stream;
    isEndOfMessage = false;
    dataOut = new ByteArrayOutputStream(DEFAULT_INIT_BUFFER_SIZE);
    this.enc = enc;
    this.cps = cps;
    this.source = source;
    this.target = target;
  }

  /* ***********************************************************************
   * FilterOutputStream implementation
   */

  public void write(byte[] b)
    throws IOException {
    dataOut.write(b);
  }

  public void write(byte[] b, int off, int len)
    throws IOException {
    dataOut.write(b, off, len);
  }

  public void write(int b)
    throws IOException {
    dataOut.write(b);
  }

  public void flush()
    throws IOException {
    throw new IOException("Buffered data cannot be flushed until end of message");
  }

  public void close()
    throws IOException {
    if (!isEndOfMessage) {
      throw new IOException("Buffered data cannot be flushed until end of message");
    }
  }

  /* **********************************************************************
   * ProtectedOutputStream implementation
   */

  public void finishOutput(MessageAttributes attributes)
    throws java.io.IOException {
    ProtectedObject pm = protectMessage();
    isEndOfMessage = true;

    ObjectOutputStream oos = new ObjectOutputStream(outputStream);
    oos.writeObject(pm);
  }

  /* ***********************************************************************
   * Private methods
   */
  private ProtectedObject protectMessage()
    throws IOException {
    SecureMethodParam policy =
      cps.getSendPolicy(source.toAddress() + ":"
			  + target.toAddress());

    if (log.isDebugEnabled()) {
      log.debug("protectMessage: " + source.toAddress()
		+ " -> " + target.toAddress());
    }

    if (policy == null) {
       throw new IOException("Could not find message policy between "
			     + source.toAddress()
			     + " and " + target.toAddress());
    }

    ProtectedObject protectedMessage = null;
    try {
      protectedMessage =
	enc.protectObject(dataOut.toByteArray(),
			  source,
			  target,
			  policy);
    }
    catch (GeneralSecurityException e) {
      throw new IOException(e.toString());
    }
    if (log.isDebugEnabled()) {
      log.debug("protectMessage OK: " + source.toAddress()
		+ " -> " + target.toAddress());
    }
    return protectedMessage;
  }
}
