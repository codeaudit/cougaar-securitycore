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
 * Created on September 12, 2001, 4:01 PM
 */

package org.cougaar.core.security.crypto;


import java.util.*;
import java.security.*;

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


