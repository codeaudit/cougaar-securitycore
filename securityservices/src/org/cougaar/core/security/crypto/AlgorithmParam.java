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


package org.cougaar.core.security.crypto;


import java.util.ArrayList;

public class AlgorithmParam {
  private static ArrayList hashList = new ArrayList();

  static
  {
    hashList.add("SHA-1/");
    hashList.add("SHA1/");
    hashList.add("SHA1with");

    hashList.add("MD5/");
    hashList.add("MD5with");

    hashList.add("MD2/");
    hashList.add("MD2with");

  }

  public static String getSigningAlgorithm(String keyalg)
  {
    String signAlg = null;
    String defaultDigest = "SHA1with";

    /* Supported signature algorithms
     * RSA: SHA1withRSA, MD5withRSA, MD2withRSA
     * DSA: SHA1withDSA
     */

    if (keyalg.equals("RSA")) {
      signAlg = defaultDigest + keyalg;
    }
    else if (keyalg.equals("DSA")) {
      signAlg = defaultDigest + keyalg;
    }
    return signAlg;
  }
}


