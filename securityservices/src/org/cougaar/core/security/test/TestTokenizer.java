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


package org.cougaar.core.security.test;

import java.util.StringTokenizer;

public class TestTokenizer {
  public static void main(String args[]) {
    System.out.println("TestJaas main()");
    TestTokenizer t = new TestTokenizer();
    String spec = "";
    if (args.length > 0) {
      spec = args[0];
    }
    String st = t.normalizeCipherSpec(spec);
    System.out.println("spec=" + st);
  }

  private String normalizeCipherSpec(String spec) {
    String newSpec = "";
    StringTokenizer st = new StringTokenizer(spec, "/");
    int count = 0;
    while (st.hasMoreTokens()) {
      String next = st.nextToken();
      newSpec = newSpec + next;
      if (count < 2) {
	newSpec = newSpec + "/";
      }
      count++;
    }
    switch (count) {
    case 0:
      // No algorithm was provided. Use default parameters
      newSpec = "DESede/ECB/PKCS#1";
      break;
    case 1:
      // Neither the cipher nor the padding algorithm were specified.
      // Some providers require this to be specified.
      // Add default parameters.
      newSpec = newSpec + "ECB/PKCS#1";
      break;
    case 2:
      // The padding algorithm was not specified.
      // Some providers require this to be specified.
      // Add default parameters.
      newSpec = newSpec + "PKCS#1";
      break;
    case 3:
      // All the parameters were specified.
      break;
    default:
      // Problem in the specification.
      // Use default parameters.
      newSpec = "DESede/ECB/PKCS#1";
      break;
    }
    return newSpec;
  }
}
