package org.cougaar.core.security.util;

import java.io.*;
import java.security.*;
import javax.crypto.*;

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
