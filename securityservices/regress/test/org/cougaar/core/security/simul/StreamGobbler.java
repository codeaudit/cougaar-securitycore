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

package test.org.cougaar.core.security.simul;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class StreamGobbler
  extends Thread
{
  public static int STDERR = 1;
  public static int STDOUT = 2;

  private InputStream is;
  private OutputStream os;
  private int bytesWritten;

  StreamGobbler(InputStream is, OutputStream os, int streamType) {
    this.is = is;
    this.os = os;
  }

  public int getWrittenBytes() {
    return bytesWritten;
  }

  public void run() {
    try {
      byte buffer[] = new byte[100];
      int bytes = 0;
      BufferedInputStream bir = new BufferedInputStream(is);
      //InputStream bir = is;

      while (bytes != -1) {
	bytes = bir.read(buffer, 0, buffer.length);
	if (bytes > 0) {
	  os.write(buffer, 0, bytes);
	  os.flush();
	  bytesWritten += bytes;
	}
      }
    }
    catch (IOException ioe) {
      ioe.printStackTrace();  
    }
  }
}
