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

import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.ProtectedInputStream;

public class MessageCipherInputStream
  extends ProtectedInputStream
{
  /** ProtectedOutputStream can read old attributes (check to see if it should
   *  write the signature. Note at this point the attributes were already sent)
   */
  private InputStream inputStream;
  private CipherInputStream cis;

  public MessageCipherInputStream(InputStream stream, Cipher c) {
    super(stream);
    inputStream = stream;
    cis = new CipherInputStream(inputStream, c);
  }

  /* ***********************************************************************************
   * FilterInputStream implementation
   */

  public int available() 
    throws IOException {
    return cis.available();
  }

  public void close() 
    throws IOException {
    cis.close();
  }

  public long skip(long n)
    throws IOException {
    return cis.skip(n);
  }

  public void reset()
    throws IOException {
    cis.reset();
  }

  public void mark(int readlimit) {
    cis.mark(readlimit);
  }

  public boolean markSupported() {
    return cis.markSupported();
  }

  public int read()
    throws IOException {
    return cis.read();
  }

  public int read(byte[] b)
    throws IOException {
    return cis.read(b);
  }

  public int read(byte[] b, int off, int len)
    throws IOException {
    return cis.read(b, off, len);
  }

  /* ***********************************************************************************
   * ProtectedInputStream implementation
   */
  public void finishInput(MessageAttributes attributes)
    throws java.io.IOException {
  }
}
