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
