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


package org.cougaar.core.security.crypto;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.InputStream;

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
