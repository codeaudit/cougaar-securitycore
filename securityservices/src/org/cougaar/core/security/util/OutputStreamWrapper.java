package org.cougaar.core.security.util;

import java.io.*;

public class OutputStreamWrapper extends OutputStream {
  private OutputStream _out;

  public OutputStreamWrapper(OutputStream out) {
    _out = out;
  }
      
  public void write(int b)
    throws IOException {
    _out.write(b);
  }

  public void write(byte[] b)
    throws IOException {
    _out.write(b);
  }


  public void write(byte[] b,
                    int off,
                    int len)
    throws IOException{
    _out.write(b,off,len);
  }


  public void flush()
    throws IOException{
    _out.flush();
  }


  public void close()
    throws IOException{
    _out.close();
  }

}
