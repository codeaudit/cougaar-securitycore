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

import java.io.IOException;
import java.io.OutputStream;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class DebugOutputStream extends OutputStreamWrapper {
  private static Logger _log;

  static {
    _log = LoggerFactory.getInstance().createLogger("DebugOutputStream");
  }

  public DebugOutputStream(OutputStream out) {
    super(out);
  }
      
  public void write(int b)
    throws IOException {
    _log.debug("1*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write byte");
                           
    super.write(b);
  }

  public void write(byte[] b)
    throws IOException {
    _log.debug("2*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write " +
                       b.length + " bytes");
    super.write(b);
    printBytes(b,0,b.length);
  }


  public void write(byte[] b,
                    int off,
                    int len)
    throws IOException{
    _log.debug("3*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 write " +
                       len + " bytes");
    super.write(b,off,len);
    printBytes(b,off,len);
  }


  public void flush()
    throws IOException{
    _log.debug("4*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 flush");
    super.flush();
  }


  public void close()
    throws IOException{
    _log.debug("5*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8*8 close");
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
        _log.debug("\n" + hex[b1] + hex[b2] + 
                         hex[b3] + hex[b4] + ":");
      } else if ((i - start) % 8 == 0) {
        _log.debug("  ");
      } 
      _log.debug(" " + hex[highNibble] + hex[lowNibble]);
    } // end of for (int i = start; i < start + len; i++)
  }
}
