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

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class DumpOutputStream extends OutputStream {
  FileOutputStream _fout;
  OutputStream     _os;
  public DumpOutputStream(OutputStream os, String filename) throws IOException {
    _fout = new FileOutputStream(filename);
    _os = os;
  }

  public synchronized void close() throws IOException {
    if (_fout != null) {
      _fout.close();
    }
    _os.close();
  }

  public synchronized void flush()throws IOException {
    if (_fout != null) {
      _fout.flush();
    }
    _os.flush();
  }

  public synchronized void write(byte[] b) throws IOException {
    if (_fout != null) {
      _fout.write(b);
    }
    _os.write(b);
  }

  public synchronized void write(byte[] b, int off, int len) 
    throws IOException {
    if (_fout != null) {
      _fout.write(b, off, len);
    }
    _os.write(b, off, len);
  }

  public synchronized void write(int b) throws IOException {
    if (_fout != null) {
      _fout.write(b);
    }
    _os.write(b);
  }

  public synchronized void stopDumping() throws IOException {
    _fout.close();
    _fout = null;
  }
}
