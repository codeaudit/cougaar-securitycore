package org.cougaar.core.security.util;

import java.io.*;

public class DebugOutputStream extends OutputStreamWrapper {
  public DebugOutputStream(OutputStream out) {
    super(out);
  }
      
  public void write(int b)
    throws IOException {
    System.out.println("1*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write byte");
                           
    super.write(b);
  }

  public void write(byte[] b)
    throws IOException {
    System.out.println("2*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write " +
                       b.length + " bytes");
    super.write(b);
    printBytes(b,0,b.length);
  }


  public void write(byte[] b,
                    int off,
                    int len)
    throws IOException{
    System.out.println("3*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write " +
                       len + " bytes");
    super.write(b,off,len);
    printBytes(b,off,len);
  }


  public void flush()
    throws IOException{
    System.out.println("4*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 flush");
    super.flush();
  }


  public void close()
    throws IOException{
    System.out.println("5*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 close");
    super.close();
  }

  private static void printBytes(byte[] b, int start, int len) {
    char[] hex = { '0','1','2','3','4','5','6','7',
                   '8','9','A','B','C','D','E','F' };
    for (int i = start; i < start + len; i++) {
      int highNibble = (b[i] & 0xF0) >> 4;
      int lowNibble  = (b[i] & 0x0F);
      if ((i - start) % 16 == 0) {
        int b1 = ((i - start) & 0xF000) >> 12;
        int b2 = ((i - start) & 0x0F00) >>  8;
        int b3 = ((i - start) & 0x00F0) >>  4;
        int b4 = ((i - start) & 0x000F);
        System.out.print("\n" + hex[b1] + hex[b2] + 
                         hex[b3] + hex[b4] + ":");
      } else if ((i - start) % 8 == 0) {
        System.out.print("  ");
      } 
      System.out.print(" " + hex[highNibble] + hex[lowNibble]);
    } // end of for (int i = start; i < start + len; i++)
    System.out.println();
  }
}
