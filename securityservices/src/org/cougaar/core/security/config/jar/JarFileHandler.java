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


package org.cougaar.core.security.config.jar;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.jar.JarFile;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.crypto.CertValidityListener;
import org.cougaar.core.security.crypto.PrivateKeyCert;
import org.cougaar.core.security.services.crypto.CertValidityService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.util.JARSigner;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.service.LoggingService;

public class JarFileHandler
  implements CertValidityListener
{
  static JarFileHandler _handler = null;
  ServiceBroker serviceBroker;
  private LoggingService log;

  Hashtable jarFiles = new Hashtable();
  X509Certificate [] certChain = null;
  PrivateKey privatekey = null;
  String nodealias = null;

  protected JarFileHandler(ServiceBroker sb) {
    serviceBroker = sb;
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
  }

  public static JarFileHandler getHandler(ServiceBroker sb) {
    if (_handler == null) {
      _handler = new JarFileHandler(sb);
    }
    return _handler;
  }

  public void updateJarFile(String fileName, File file, ByteArrayOutputStream bos) {
    try {
      JARSigner.updateJarEntry(fileName, file, bos);
    }
    catch (IOException e) {
      log.error("Unable to modify policy file" + e);
      return;
    }
    // does it need to be signed?
    boolean signed = false;
    try {
      signed = signJarFile(file);
    }
    catch (Exception e) {
      log.error("Unable to sign policy jar file" + e);
    }

    if (!signed) {
      // save when listener updateCertificate is called
      CertValidityService cvs = (CertValidityService)
        serviceBroker.getService(this,
                                 CertValidityService.class, null);
      cvs.addValidityListener(this);
      jarFiles.put(file.getPath(), file.getPath());
      serviceBroker.releaseService(this, CertValidityService.class, cvs);
    }
  }

  public boolean signJarFile(File file) {
    if (nodealias != null && privatekey != null && certChain != null
      && certChain.length != 0) {
      if (log.isDebugEnabled()) {
        log.debug("Signing jar: " + file.getPath() + " with key alias "
		  + nodealias);
      }

      try {
        JARSigner signer = new JARSigner(nodealias, privatekey, certChain);
        JarFile jar = new JarFile(file, false);

        ByteArrayOutputStream jos = new ByteArrayOutputStream();
        signer.signJarFile(jar, jos);
        FileOutputStream jarOut = new FileOutputStream(file);
        jarOut.write(jos.toByteArray());
	jarOut.close();
	jos.close();

        if (log.isDebugEnabled()) {
          log.debug("Signed jar: " + file.getPath());
        }
        return true;
      } catch (Exception iox) {
        log.warn("Exception in signing jar file: " + file.getPath()
	  + " - " + iox);
      }
    }
    else {
      if (log.isDebugEnabled()) {
        log.debug("No certificate available to sign yet.");
      }
    }
    return false;
  }

  // interface
  public String getName() {
    // listening for node certificate
    return NodeInfo.getNodeName();
  }

  public void invalidate(String cname) {}

  /** Update certificate after checkOrMakeCert
   * CertValidityListener callback
   */
  public void updateCertificate() {
    KeyRingService keyRing = (KeyRingService)
      serviceBroker.getService(this,
                               KeyRingService.class, null);

    String nodename = getName();
    nodealias =  keyRing.findAlias(nodename);
    List keyList = keyRing.findPrivateKey(nodename);
    if (keyList != null && keyList.size() > 0) {
      PrivateKeyCert keyCert = (PrivateKeyCert)keyList.get(0);
      privatekey = keyCert.getPrivateKey();
      try {
        certChain = keyRing.checkCertificateTrust(
          keyCert.getCertificateStatus().getCertificate());
      } catch (CertificateException cex) {
        log.error("a new cert is invalid: " + nodename);
      }
    }

    serviceBroker.releaseService(this, KeyRingService.class, keyRing);

    if (log.isDebugEnabled()) {
      log.debug("notified cert: " + nodealias + ", " + privatekey);
    }

    synchronized (jarFiles) {
      for (Enumeration en = jarFiles.keys(); en.hasMoreElements(); ) {
        String fileName = (String)en.nextElement();
        File file = new File(fileName);
        if (signJarFile(file)) {
          jarFiles.remove(fileName);
        }
      }
    }
  }
}
