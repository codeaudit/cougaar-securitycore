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


package org.cougaar.core.security.policy.enforcers.util;

import javax.xml.parsers.DocumentBuilder; 
import javax.xml.parsers.DocumentBuilderFactory;  
import javax.xml.parsers.ParserConfigurationException;
 
import java.io.InputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import org.xml.sax.SAXException;  

/*
 * This class maps OWL names of Cipher Suite Sets to their Ultra*Log
 * implementations.
 */

public class CipherSuiteMapping
{
  private HashMap cipherMap;
  protected static Logger _log;
  static {
    _log = LoggerFactory.getInstance().createLogger(CipherSuiteMapping.class);
  }

  private final static String file = "OwlMapCipherSuite.xml";
  private final static String SYMMETRIC = "symmetric";
  private final static String ASYMMETRIC = "asymmetric";
  private final static String SIGNATURE = "signature";

  public CipherSuiteMapping()
    throws IOException
  {
    cipherMap = new HashMap();
    ConfigFinder cf = ConfigFinder.getInstance();
    InputStream mapping = cf.open(file);
    parse(mapping);
  }


  private void parse(InputStream is)
    throws IOException
  {
    DocumentBuilderFactory factory =
      DocumentBuilderFactory.newInstance();
    if (_log.isDebugEnabled()) {
      _log.debug("found a factory = " + factory);
    }
    
    try {
      DocumentBuilder builder = factory.newDocumentBuilder();
      if (_log.isDebugEnabled()) {
        _log.debug("new document builder = " + builder);
      }
      Document document = builder.parse(is);
      Node head = document.getFirstChild();
      if (!head.getNodeName().equals("ciphers")) {
        if (_log.isDebugEnabled()) {
          _log.warn("Head name actually = " + head.getNodeName());
        }
        throw new IOException("Wrong type of file");
      }     
      for (Node cipher = head.getFirstChild();
           cipher != null;
           cipher = cipher.getNextSibling()) {
        addCipherSuite(cipher);
      }
      is.close();
      if (_log.isDebugEnabled()) {
        _log.debug("document = " + document);
      }
    } catch (SAXException sxe) {
           // Error generated during parsing)
      Exception  x = sxe;
      if (sxe.getException() != null)
        x = sxe.getException();
      x.printStackTrace();
    } catch (ParserConfigurationException pce) {
      // Parser with specified options can't be built
      pce.printStackTrace();
    } catch (IOException ioe) {
      // I/O error
      ioe.printStackTrace();
    }
  }

  private void addCipherSuite(Node cipher)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("entering addCipherSuite");
    }
    printNode(cipher);
    NamedNodeMap nnm = cipher.getAttributes();
    if (nnm == null || nnm.getNamedItem("name") == null) {
      // I don't know what these are but each cipher is preceeded by one 
      // of these
      return;
    } 
    String name    = ULOntologyNames.cipherPrefix  
                          + nnm.getNamedItem("name").getNodeValue();
    CipherSuite cs = new CipherSuite(name);
    cipherMap.put(name,cs);
    if (_log.isDebugEnabled()) {
      _log.debug("Created a cipher suite with name " + name);
      _log.debug("Looking for cipher mods");
    }

    for (Node cipherUpdate = cipher.getFirstChild();
         cipherUpdate != null;
         cipherUpdate = cipherUpdate.getNextSibling()) {
      addCipherUpdate(cs, cipherUpdate);
    }

  }

  private void addCipherUpdate(CipherSuite cs, Node update)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Modification of a cipher");
    }
    printNode(update);
    if (_log.isDebugEnabled()) {
      _log.debug("showing the children of the cipher update");
    }
    if (update.getNodeType() != Node.ELEMENT_NODE) {
      if (_log.isDebugEnabled()) {
        _log.debug("Not  an element node - returning");
      }
      return;
    }
    String modType = update.getNodeName();
    String text    = null;
    for (Node child = update.getFirstChild(); 
         child != null;
         child = child.getNextSibling()) {
      printNode(child);
      if (child.getNodeType() == Node.TEXT_NODE &&
          child.getNodeName().equals("#text")) {
        text = child.getNodeValue();
      }
      if (text != null) {
        if (_log.isDebugEnabled()) {
          _log.debug("Got what I wanted - breaking out");
        }
        break;
      }
    }
    if (text == null || modType == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("missed attribute - skipping cipher update");
      }
      return;
    }
    if (modType.equals(SYMMETRIC)) {
      if (_log.isDebugEnabled()) {
        _log.debug("Adding symmetric alg " + text);
      }
      cs.addSymmetric(text);
    } else if (modType.equals(ASYMMETRIC)) {
      if (_log.isDebugEnabled()) {
        _log.debug("Adding asymmetric alg " + text);
      }
      cs.addAsymmetric(text);
    } else if (modType.equals(SIGNATURE)) {
      if (_log.isDebugEnabled()) {
        _log.debug("Adding signature alg " + text);
      }
      cs.addSignature(text);
    }
  }

  private static void printNode(Node node)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("------------Node---------------");
      _log.debug(" name = " + node.getNodeName());
      _log.debug(" value = " + node.getNodeValue());
      _log.debug(" type = " + node.getNodeType());
      NamedNodeMap nnm = node.getAttributes();
      if (nnm == null) { 
        _log.debug("No attributes");
      } else {
        for (int i = 0; i < nnm.getLength(); i++) {
          Node attr = nnm.item(i);
          _log.debug("  attribute name = " + attr.getNodeName());
          _log.debug("  attribute value = " + attr.getNodeValue());
          _log.debug("  attribute type = " + attr.getNodeType());
        }
      }
      _log.debug("---------That's all---------------");
    }
  }

  public CipherSuite ulCiphersFromKAoSProtectionLevel(Set ciphers)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Entering ulCiphersFromKAoSProtectionLevel");
    }
    CipherSuite cs = new CipherSuite();
    for(Iterator cipherIt = ciphers.iterator(); cipherIt.hasNext();) {
      String cipher = (String) cipherIt.next();
      CipherSuite subcs = (CipherSuite) cipherMap.get(cipher);

      if (_log.isDebugEnabled()) {
        _log.debug("Examining cipher = " + cipher);
      }
      if (subcs != null) {
        if (_log.isDebugEnabled()) {
          _log.debug("found a match in the CipherSuiteMapping");
        }
        cs.addAll(subcs);
      } else {
        if (_log.isWarnEnabled()) {
          _log.warn("No cipher suite with that name");
        }
      }
    }
    if (_log.isDebugEnabled()) {
      _log.debug("Exiting ulCiphersFromKAoSProtectionLevel");
    }
    return cs;
  }

  public Set usedProtectionLevelValues()
  {
    return cipherMap.keySet();
  }
}
