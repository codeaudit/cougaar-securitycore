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

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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
