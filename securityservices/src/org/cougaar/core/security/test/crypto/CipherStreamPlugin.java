/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
 */


package org.cougaar.core.security.test.crypto;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.service.*;
import org.cougaar.core.service.community.*;
import org.cougaar.core.mts.MessageAddress;

import org.cougaar.core.security.provider.*;

import javax.crypto.*;
import java.security.*;
import java.util.*;
import java.io.*;

public class CipherStreamPlugin
  extends ComponentPlugin
{
  private String spec;
  private LoggingService log;
  public int bufferSize;
  public int streamSize;

  public void setParameter(Object o){
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() != 3) {
      throw new IllegalArgumentException(this.getClass().getName()
					 + " should take 1 parameter, got " + l.size()
					 + ". Fix configuration file");
    }
    else {
      spec = l.get(0).toString();
      bufferSize = Integer.valueOf(l.get(1).toString()).intValue();
      streamSize = Integer.valueOf(l.get(2).toString()).intValue();
    }
  }

  public static void main(String[] args) {
    CipherStreamPlugin csp = new CipherStreamPlugin();

    csp.bufferSize = Integer.valueOf(args[0]).intValue();
    csp.streamSize = Integer.valueOf(args[1]).intValue();
    csp.runTest();
  }

  /**
   * 
   */
  protected void setupSubscriptions() {
    runTest();
  }

  private void runTest() {
    if (getBindingSite() == null) {
      SecurityServiceProvider ssp = new SecurityServiceProvider();
      ServiceBroker sb = ssp.getServiceBroker();
      log = (LoggingService)sb.getService(this, LoggingService.class, null);
      if (log == null) {
	System.err.println("Unable to get logging service");
	return;
      }
   }
    else {
      log = (LoggingService)getBindingSite().getServiceBroker().getService
	(this, LoggingService.class, null);
    }
    String cipherSpecs[] = {
      "AES", "Blowfish", "DES", "DESede",
      "RC2", "RC4", "RC5",
      "RSA"
    };
    //"PBEWithMD5AndDES", "PBEWithHmacSHA1AndDESede",

    String modeSpecs[] = {
      "NONE", "CBC", "CFB", "ECB", "OFB", "PCBC"
    };

    String paddingSpecs[] = {
      "NoPadding", "OAEPWithMD5AndMGF1Padding", "PKCS5Padding"
    };
    //"SSL3Padding"

    String keyGeneratorSpecs[] = {
      "AES", "Blowfish", "DES", "DESede", "HmacMD5", "HmacSHA1"
    };

    int experimentNumber = 0;
    int keysize = 128;
    System.out.println("experimentNumber, keysize, cipherSpec, keyGenSpec"
		       + ", diff21"
		       + ", diff32"
		       + ", diff43"
		       + ", diff54"
		       + ", diff65"
		       + ", diff61"
      );

    Experiment exp = new Experiment();

    for (int j = 0 ; j < cipherSpecs.length ; j++) {
      for (int k = 0 ; k < keyGeneratorSpecs.length ; k++) {
	for (int l = 0 ; l < modeSpecs.length ; l++) {
	  for (int m = 0 ; m < paddingSpecs.length ; m++) {
	    try {
	      String transform = cipherSpecs[j] + "/" + modeSpecs[l] + "/" + paddingSpecs[m];
	      for (int i = 0 ; i < 4 ; i++) {
		experimentNumber++;

		exp.experimentNumber = experimentNumber;
		exp.cipherSpec = transform;
		exp.keyGenSpec = keyGeneratorSpecs[k];
		exp.bufferSize = bufferSize;
		exp.streamSize = streamSize;
		exp.keysize = keysize;
		exp.diff21 = 0;
		exp.diff32 = 0;
		exp.diff43 = 0;
		exp.diff54 = 0;
		exp.diff65 = 0;
		exp.diff61 = 0;

		testStreamEncryption(exp);
	      }
	    }
	    catch (Exception e) {
	      log.error("Unable to encrypt", e);
	      printResults(exp, e.toString());
	    }
	  }
	}
      }
    }
  }

  private void testStreamEncryption(Experiment exp)
    throws Exception {

    if (exp.keyGenSpec.equals("DES") || exp.cipherSpec.equals("DES")) {
      // Key length must 56
      exp.keysize = 56;
    }
    else if (exp.keyGenSpec.equals("DESede") || exp.cipherSpec.equals("DESede")) {
      // Key length must be 112 or 168
      exp.keysize = 112;
    }

    log.info("Test stream encryption. Cipher=" + exp.cipherSpec
	     + " - keygen=" + exp.keyGenSpec
	     + " - keylength=" + exp.keysize
	     + " - buffer size=" + exp.bufferSize
	     + " - stream size=" + exp.streamSize);
    long date1 = new Date().getTime();
    SecretKey sk = null;
    SecureRandom random = new SecureRandom();
    KeyGenerator kg = KeyGenerator.getInstance(exp.keyGenSpec);
    kg.init(exp.keysize, random);
    sk = kg.generateKey();
    
    long date2 = new Date().getTime();
    exp.diff21 = date2 - date1;

    Cipher ci;
    ci=Cipher.getInstance(exp.cipherSpec);
    ci.init(Cipher.ENCRYPT_MODE, sk);

    long date3 = new Date().getTime();
    exp.diff32 = date3 - date2;

    String fileName = System.getProperty("org.cougaar.workspace")
      + File.separator + "encryptedStream" + exp.experimentNumber + ".dat";
    FileOutputStream fos = new FileOutputStream(fileName);
    CipherOutputStream cos = new CipherOutputStream(fos, ci);
     
    long date4 = new Date().getTime();
    exp.diff43 = date4 - date3;

    dumpData(cos, exp.bufferSize, exp.streamSize);
    long date5 = new Date().getTime();
    exp.diff54 = date5 - date4;

    cos.close();
    long date6 = new Date().getTime();
    exp.diff65 = date6 - date5;
    exp.diff61 = date6 - date1;

    log.info("date2 - date1=" + (exp.diff21));
    log.info("date3 - date2=" + (exp.diff32));
    log.info("date4 - date3=" + (exp.diff43));
    log.info("date5 - date4=" + (exp.diff54));
    log.info("date6 - date5=" + (exp.diff65));
    log.info("date6 - date1=" + (exp.diff61));

    printResults(exp, "");
  }

  private void printResults(Experiment exp, String msg) {
    System.out.println(exp.experimentNumber
		       + ", " + exp.keysize
		       + ", " + exp.cipherSpec + ", " + exp.keyGenSpec
		       + ", " + (exp.diff21)
		       + ", " + (exp.diff32)
		       + ", " + (exp.diff43)
		       + ", " + (exp.diff54)
		       + ", " + (exp.diff65)
		       + ", " + (exp.diff61)
		       + ", " + msg
      );
  }

  private class Experiment
  {
    public int experimentNumber;
    public String cipherSpec;
    public String keyGenSpec;
    public int keysize;

    public long diff21;
    public long diff32;
    public long diff43;
    public long diff54;
    public long diff65;
    public long diff61;

    public int bufferSize;
    public int streamSize;
  }

  private void dumpData(OutputStream os, int bufferLength, int streamLength)
    throws IOException {
    byte[] data = new byte[bufferLength];
    for (int i = 0 ; i < (streamLength / bufferLength) ; i++) {
      os.write(data);
    }
  }

  /**
   * Top level plugin execute loop.  
   */
  protected void execute () {
	
  }


}
