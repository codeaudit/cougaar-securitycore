package org.cougaar.core.security.util;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

public class OnTopCipherInputStream extends FilterInputStream {
  private InputStream _unfiltered;
  private int         _blockSize;
  private ClosingInputStream _closing;
  private Logger _log;

  public OnTopCipherInputStream(InputStream is, Cipher c) {
    super(null);
    _log = LoggerFactory.getInstance().createLogger(this);
    _unfiltered = is;
    _blockSize = c.getBlockSize();
    if (_blockSize > 0) {
      _closing = new ClosingInputStream(is, _blockSize);
      is = _closing;
    }
    super.in = new CipherInputStream(is, c);
  }
  
  public void doFinal() throws IOException {
    // Push an extra block of data. This lets the OnTopCipherInputStream
    // recover and close when it is done, too
    if (_closing != null) {
      try {
      // give the receiver an extra two blocks of data so that it
      // has time to close
//       System.out.println("done reading");
      _closing.doneReading();
      // now just read the last two blocks of data:
      int left = _blockSize;
      while (left > 0) {
        int b = read();
        if (b == -1) {
          return;
        } else {
          left--;
        }
      }
      } catch (Throwable e) {
	if (_log.isWarnEnabled()) {
	  _log.warn("Unable to close cipher", e);
	}
      }
    }
  }

  private static class ClosingInputStream extends FilterInputStream {
    boolean _done      = false;
    int     _byteCount = 0;
    int     _blockSize;

    public ClosingInputStream(InputStream is, int blockSize) {
      super(is);
      _blockSize = blockSize;
    }

    public int available() throws IOException {
      if (_done) {
        int left = _blockSize - _byteCount % _blockSize;
        if (left == _blockSize) {
          return 0;
        }
        int avail = super.available();
        if (avail >= left) {
          return left;
        } else {
          return avail;
        }
      }
      return super.available();
    }

    public void skip(int len) throws IOException {
      if (_done && _byteCount % _blockSize == 0) {
        throw new EOFException();
      }
      super.skip(len);
    }

    public int read() throws IOException {
      if (_done && (_byteCount % _blockSize == 0)) {
        return -1;
      }
      int b = super.read();
      if (b != -1) {
        _byteCount++;
      }
      return b;
    }

    public int read(byte[] b) throws IOException {
      if (_done && (_byteCount % _blockSize == 0)) {
        return -1;
      }
      int avail = available();
      int len = b.length;
      if (len > avail) {
        len = avail;
      }
      int bytes = super.read(b, 0, len);
      if (bytes > 0) {
        _byteCount += bytes;
      }
      return bytes;
    }

    public int read(byte[] b, int offset, int len) throws IOException {
      if (_done && (_byteCount % _blockSize == 0)) {
        return -1;
      }
      int avail = available();
      if (len > avail) {
        len = avail;
      }
      int bytes =  super.read(b, offset, len);
      if (bytes > 0) {
        _byteCount += bytes;
      }
      return bytes;
    }

    public void doneReading() {
      _done = true;
    }
  }
}
