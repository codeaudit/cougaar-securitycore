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

package org.cougaar.core.security.crypto;

import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.lang.ClassNotFoundException;
import java.security.GeneralSecurityException;
import java.util.Iterator;

// Cougaar core services
import org.cougaar.core.mts.ProtectedInputStream;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.services.crypto.EncryptionService;
import org.cougaar.core.security.services.crypto.CryptoPolicyService;
import org.cougaar.core.security.crypto.ProtectedObject;
import org.cougaar.core.security.policy.CryptoPolicy;

public class MessageInputStream
  extends ProtectedInputStream
{
  /** ProtectedOutputStream can read old attributes (check to see if it should
   *  write the signature. Note at this point the attributes were already sent)
   */
  private InputStream inputStream;
  private boolean isEndOfMessage;
  private boolean isClosed;
  private EncryptionService enc;
  private CryptoPolicyService cps;
  private MessageAddress source;
  private MessageAddress target;
  private ByteArrayInputStream plainTextInputStream;
  private ServiceBroker serviceBroker;
  private LoggingService log;

  public MessageInputStream(InputStream stream,
			    EncryptionService enc,
			    CryptoPolicyService cps,
			    MessageAddress source,
			    MessageAddress target,
			    ServiceBroker sb) {
    super(stream);
    serviceBroker = sb;

    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);

    inputStream = stream;
    isEndOfMessage = false;
    isClosed = false;
    this.enc = enc;
    this.cps = cps;
    this.source = source;
    this.target = target;

  }

  /* ************************************************************************
   * FilterInputStream implementation
   */
  public int read()
    throws IOException {
    if (!isEndOfMessage) {
      readInputStream();
    }
    return plainTextInputStream.read();
  }

  public int read(byte[] b)
    throws IOException {
    if (!isEndOfMessage) {
      readInputStream();
    }
    return plainTextInputStream.read(b);
  }

  public int read(byte[] b, int off, int len)
    throws IOException {
    if (!isEndOfMessage) {
      readInputStream();
    }
    return plainTextInputStream.read(b, off, len);
  }

  public long skip(long n)
    throws IOException {
    if (!isEndOfMessage) {
      readInputStream();
    }
    return plainTextInputStream.skip(n);
  }

  public int available()
    throws IOException {
    if (!isEndOfMessage) {
      readInputStream();
    }
    return plainTextInputStream.available();
  }

  public void close()
    throws IOException {
    isClosed = true;
    inputStream.close();
  }

  public void mark(int readlimit) {
  }

  public void reset()
    throws IOException {
    throw new IOException("reset not supported by this stream");
  }

  public boolean markSupported() {
    return false;
  }


  /* ***********************************************************************
   * ProtectedInputStream implementation
   */
  public void finishInput(MessageAttributes attributes)
    throws java.io.IOException {
    if (!isEndOfMessage) {
      readInputStream();
    }
  }

  /* ***********************************************************************
   * Private methods
   */
  private void readInputStream()
    throws IOException {
    if (isClosed) {
      if (log.isWarnEnabled()) {
	log.warn("readInputStream NOK: " + source.toAddress()
		 + " -> " + target.toAddress()
		 + " - Stream is closed");
      }
      throw new IOException("InputStream is closed");
    }
    ObjectInputStream ois = new ObjectInputStream(inputStream);

    if (log.isDebugEnabled()) {
      log.debug("readInputStream: " + source.toAddress()
		+ " -> " + target.toAddress());
    }

    // The object should be a ProtectedObject
    ProtectedObject protectedObject = null;
    try {
      protectedObject = (ProtectedObject) ois.readObject();
    }
    catch (ClassNotFoundException e) {
      if (log.isWarnEnabled()) {
	log.warn("readInputStream NOK: " + source.toAddress()
		 + " -> " + target.toAddress()
		 + " - Class not found: " + e);
      }
      throw new IOException("Unexpected data in the stream:" + e);
    }

    SecureMethodParam smp = null;
    CryptoPolicy cp = cps.getOutgoingPolicy(source.toAddress());
    byte[] rawData = null;
    
    if (cp == null) {
      if (log.isWarnEnabled()) {
        log.warn("readInputStream NOK: " + source.toAddress()
           + " -> " + target.toAddress()
           + " - No policy");
      }
      throw new IOException("Could not find message policy between "
			    + source.toAddress()
			    + " and " + target.toAddress());
    }

    /* assembly SecureMethodParam:
     * as CryptoPolicy can contain multiple entries for each parameter,
     * every meaningful combinations needs to be checked before declare
     * a failure, i.e. throwing IOException
     */
    String method = "";
    Iterator iter = (cp.getSecuMethod(target.toAddress())).iterator();
    while(iter.hasNext()){
      method = (String)iter.next();
      if(method.equalsIgnoreCase("plain")){
        smp.secureMethod = SecureMethodParam.PLAIN;
        if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
          rawData = getRawData(protectedObject, smp, iter.hasNext());
          if(rawData!=null) break;
        }
      }else if(method.equalsIgnoreCase("sign")){ 
        smp.secureMethod = SecureMethodParam.SIGN;
        if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
          Iterator iter2 = (cp.getSignSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.signSpec = (String)iter2.next();
            rawData = getRawData(protectedObject, smp, 
                        iter.hasNext() && iter2.hasNext());
            if(rawData!=null) break;
          }
          if(rawData!=null) break;
        }
      }else if(method.equalsIgnoreCase("encrypt")){ 
        smp.secureMethod = SecureMethodParam.ENCRYPT;
        if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
          Iterator iter2 = (cp.getSymmSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.symmSpec = (String)iter2.next();
            Iterator iter3 = (cp.getAsymmSpec(target.toAddress())).iterator();
            while(iter3.hasNext()){
              smp.asymmSpec = (String)iter3.next();
              rawData = getRawData(protectedObject, smp, 
                iter.hasNext() && iter2.hasNext() && iter3.hasNext());
              if(rawData!=null) break;
            }
            if(rawData!=null) break;
          }
          if(rawData!=null) break;
        }
      }else if(method.equalsIgnoreCase("signAndEncrypt")){ 
        smp.secureMethod = SecureMethodParam.SIGNENCRYPT;
        if (smp.secureMethod == protectedObject.getSecureMethod().secureMethod){
          Iterator iter2 = (cp.getSymmSpec(target.toAddress())).iterator();
          while(iter2.hasNext()){
            smp.symmSpec = (String)iter2.next();
            Iterator iter3 = (cp.getAsymmSpec(target.toAddress())).iterator();
            while(iter3.hasNext()){
              smp.asymmSpec = (String)iter3.next();
              Iterator iter4 = (cp.getSignSpec(target.toAddress())).iterator();
              while(iter4.hasNext()){
                smp.signSpec = (String)iter4.next();
                rawData = getRawData(protectedObject, smp, 
                  iter.hasNext() && iter2.hasNext() 
                    && iter3.hasNext() && iter4.hasNext());
                if(rawData!=null) break;
              }
              if(rawData!=null) break;
            }
            if(rawData!=null) break;
          }
          if(rawData!=null) break;
        }
      }else{
        smp.secureMethod = SecureMethodParam.INVALID;
        if (log.isErrorEnabled()) {
          log.error("readInputStream NOK: " + source.toAddress()
             + " -> " + target.toAddress()
             + "invalid secure method.");
        }
        throw new IOException("invalid secure method.");
      }
    }

    if (log.isDebugEnabled()) {
      log.debug("readInputStream OK: " + source.toAddress()
		+ " -> " + target.toAddress());
    }

    plainTextInputStream = new ByteArrayInputStream(rawData);
    isEndOfMessage = true;
  }
  
  private byte[] getRawData(ProtectedObject obj, 
              SecureMethodParam policy, boolean goOn)
              throws IOException
  {
    try {
      return (byte[]) enc.unprotectObject(source,
               target,
               obj, policy);
    }
    catch (GeneralSecurityException e) {
      if(goOn) return null;
      if (log.isWarnEnabled()) {
        log.warn("readInputStream NOK: " + source.toAddress()
           + " -> " + target.toAddress()
           + e);
      }
      throw new IOException(e.toString());
    }
  }
}
