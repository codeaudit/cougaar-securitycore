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
 *
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.crypto;

import org.cougaar.util.ConfigFinder;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.Security;
import java.security.Provider;
import java.io.*;
import java.util.*;

/** This class provides a method to dynamically load
    cryptographic service providers.
    Note: The JCE framework has been implemented by several organizations,
    including SUN. SUN's JCE framework requires all cryptographic providers
    to be signed by SUN. This is not the case of other JCE frameworks,
    such as the framework provided by Cryptix. Only one framework should be used.
    * SUN framework: jce1_2_1.jar, US_export_policy.jar, local_policy.jar
    * Cryptix framework: cryptix-jce-api.jar

    Multiple providers may be used. For example:
    * SUN JCE: sunjceprovider.jar
    * Cryptix: cryptix-jce-provider.jar

    The cryptix provider cannot be used if using SUN's JCE framework because
    cryptix has not been signed by SUN.

    On the other hand, the SUN JCE cannot be used with Cryptix's framework
    because the SUN JCE only accepts a signed JCE framework.
*/

public class CryptoProviders {

  /**  Dynamically load Crypto providers */
  /** This function is commented as Crypto Providers are loaded from 
   * BaseBootstrapper 
   **/
  public static void loadCryptoProviders() {
  }

  public static void printProviderProperties() {
    Provider[] pv = Security.getProviders();
    for (int i = 0 ; i < pv.length ; i++) {
      System.out.println("Provider[" + i + "]: " + pv[i].getName() + " - Version: " + pv[i].getVersion());
      System.out.println(pv[i].getInfo());
      // List properties
      Enumeration properties = pv[i].propertyNames();
      while (properties.hasMoreElements()) {
	String key, value;
	key = (String) properties.nextElement();
	value = pv[i].getProperty(key);
	System.out.println("Key: " + key + " - Value: " + value);
      }
    }
  }

  protected static Element[] findChildElements(Node parent, String childname) {
    NodeList nlist = parent.getChildNodes();
    int nlength = nlist.getLength();
    Element[] sparseChildren = new Element[nlength];
    int nChildren = 0;
    for (int i = 0; i < nlength; i++) {
      Node tnode = (Node)nlist.item(i);
      if ((tnode.getNodeType() == Node.ELEMENT_NODE) && 
          (tnode.getNodeName().equals(childname)))  {
        sparseChildren[nChildren++] = (Element)tnode;
      }
    }
    Element[] fullChildren = new Element[nChildren];
    System.arraycopy(sparseChildren,0,fullChildren,0,nChildren);
    return fullChildren;
  }
}
