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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

public class OnTopCipherOutputStream extends FilterOutputStream {
  private OutputStream _unfiltered;
  private int          _blockSize;

  public OnTopCipherOutputStream(OutputStream os, Cipher c) {
    super(createOutputStream(os, c));
    _unfiltered = os;
    _blockSize = c.getBlockSize();
  }

  private static OutputStream createOutputStream(OutputStream os, Cipher c) {
    if (c.getBlockSize() > 0) {
      os = new NoCloseOutputStream(os);
    }
    return new CipherOutputStream(os, c);
  }

  public void close() throws IOException {
    super.close();
    if (_blockSize > 0) {
      _unfiltered.close();
    }
  }

  public void doFinal() throws IOException {
    // Push an extra block of data. This lets the OnTopCipherInputStream
    // recover and close when it is done, too
    if (_blockSize > 0) {
      // give the receiver an extra two blocks of data so that it
      // has time to close
      this.out.write(new byte[_blockSize]);
      super.close();
    }
  }

  private static class NoCloseOutputStream extends FilterOutputStream {

    public NoCloseOutputStream(OutputStream out) {
      super(out);
    }
  
    public void close() throws IOException {
      flush();
      // don't close
    }
  }
}
