/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */
package org.cougaar.core.security.test.dataprotection;

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.AlarmService;
import org.cougaar.core.agent.service.alarm.Alarm;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.FileOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.BufferedReader;
import java.security.Provider;
import java.security.Security;
import java.security.SecureRandom;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.Random;
import java.util.Date;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Hashtable;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class StreamPerformance
{
  private final int MAX_STRING_SIZE = 1000;
  private FileOutputStream _fos;
  private ObjectOutputStream _theOutputStream;
  private String _fileName;
  private ByteArrayOutputStream _bos;
  private ObjectOutputStream _oos;
  private long _objectSetSize;
  private Random _random = new Random();
  private Logger _log;
  private boolean _signStream = true;

  public StreamPerformance() {
    _log = LoggerFactory.getInstance().createLogger(this);
    _log.debug("Starting Test");
    _bos = new ByteArrayOutputStream();
    try {
      _oos = new ObjectOutputStream(_bos);
    }
    catch (Exception e) {
      _log.warn("Unable to create ObjectOutputStream", e);
    }
  }

  public void writeFile() {
    try {
      _fos = new FileOutputStream(_fileName);
      List aList = createObjects(_objectSetSize);
      _theOutputStream = new ObjectOutputStream(_fos);
      saveObjects(aList, _theOutputStream);
    }
    catch (Exception e) {
      _log.warn("Unable to write to file", e);
    }
  }
  public void setFileName(String f) {
    _fileName = f;
  }

  public void setObjectSetSize(long s) {
    _objectSetSize = s;
  }

  public static void main(String argv[]) {
    StreamPerformance sp = new StreamPerformance();
    sp.setFileName(argv[0]);
    long size = Long.parseLong(argv[1].toString()) * 1024;
    sp.setObjectSetSize(size);

    sp.loadCryptoProviders(ClassLoader.getSystemClassLoader());

    sp.runEncryptionTest();
    //sp.writeFile();
  }

  private void saveObjects(List aList, ObjectOutputStream oos) {
    try {
      Date d1 = new Date();
      oos.writeObject(aList);
      Date d2 = new Date();
      _log.debug("Time to save objects to file: " + ((d2.getTime() - d1.getTime()) / 1000) + "s" );
    }
    catch (Exception e) {
      _log.warn("Unable to write List", e);
    }
  }

  private List createObjects(long objectSetSize) {
    Date d1 = new Date();
    List aList = new ArrayList();
    long cumulatedSize = 0;
    long numberOfObjects = 0;
    while (cumulatedSize < objectSetSize) {
      cumulatedSize += createObject(aList);
      numberOfObjects++;
      /*
      if ((cumulatedSize % 10000) == 0) {
	_log.debug("Saving objects: size=" + (cumulatedSize / 1024)
		   + "KB - objects:" + numberOfObjects 
		   + " - average size=" + cumulatedSize / numberOfObjects);
      }
      */
    }
    _log.debug("Done Saving objects: size=" + (cumulatedSize / 1024)
	       + "KB - objects:" + numberOfObjects 
	       + " - average size=" + cumulatedSize / numberOfObjects);
    Date d2 = new Date();
    _log.debug("Time to create objects: " + ((d2.getTime() - d1.getTime()) / 1000) + "s" );

    return aList;
  }

  private long createObject(List aList) {
    int stringSize = _random.nextInt(MAX_STRING_SIZE);
    StringBuffer sb = new StringBuffer(stringSize);
    for (int i = 0 ; i < stringSize ; i++) {
      sb.append((char)_random.nextInt());
    }
    MyObject mo = new MyObject(10, sb.toString());
    long size = getObjectSize(mo);
    //_log.debug("stringSize=" + stringSize + " - sb.size=" + sb.toString().length()
    // + " - o.size=" + size);
    aList.add(mo);

    return size;
  }

  public long getObjectSize(Object o) {
    _bos.reset();
    try {
      _oos.writeObject(o);
    }
    catch (java.io.IOException ex) {
      _log.warn("Unable to write object to stream", ex);
    }
    return _bos.size();
  }


  public static String _cipherSpecs[] = {
    "AES", "Blowfish", "DES", "DESede",
    "RC2", "RC4", "RC5",
    "RSA"
  };
  //"PBEWithMD5AndDES", "PBEWithHmacSHA1AndDESede",

  public static String _modeSpecs[] = {
//    "NONE", "CBC", "CFB", "ECB", "OFB", "PCBC"
    "ECB"
  };

  public static String _paddingSpecs[] = {
    "NoPadding"
  };

  // , "PKCS5Padding"
  //"SSL3Padding"
  //"OAEPWithMD5AndMGF1Padding", 

  public static String _keyGeneratorSpecs[] = {
    //"AES", "Blowfish", "DES", "DESede", "HmacMD5", "HmacSHA1"
    "AES", "Blowfish", "DES", "DESede"
  };

  // Size of buffer in KB
  public static int _bufferSizeArray[] = {
//    10, 1000, 5000, 10000, 50000, 100000, 150000
    75000, 100000
  };

  private void runEncryptionTest() {
    Experiment exp = new Experiment();

    // Run with default provider
    runSuite(exp, null);

    // Run with specified provider
    /*
    Provider[] providers = Security.getProviders();
    for (int i = 0 ; i < providers.length ; i++) {
      runSuite(exp, providers[i]);
    }
    */
  }

  private void runSuite(Experiment exp, Provider provider) {
    int keysize = 128;

    // try without encryption

    for (int i = 0 ; i < _bufferSizeArray.length ; i++) {
      keysize = 0;
      exp.streamSize = _bufferSizeArray[i] * 1024;
      executeExperiment(exp, keysize, provider);
    }

    for (int i = 0 ; i < _bufferSizeArray.length ; i++) {
      keysize = 128;
      exp.streamSize = _bufferSizeArray[i] * 1024;
      executeExperiment(exp, keysize, provider);
    }


    for (int i = 0 ; i < _bufferSizeArray.length ; i++) {
      keysize = 256;
      exp.streamSize = _bufferSizeArray[i] * 1024;
      executeExperiment(exp, keysize, provider);
    }

  }

  private void executeExperiment(Experiment exp, int keysize,
				 Provider provider) {

    /*
    _log.debug("experimentNumber, streamSize, "
	       + "keysize, cipherSpec, keyGenSpec"
	       + ", provider"
	       + ", diff21"
	       + ", diff32"
	       + ", diff43"
	       + ", diff54"
	       + ", diff65"
	       + ", diff61"
      );
    */
    if (keysize == 0) {
      try {
	exp.experimentNumber++;
	exp.cipherSpec = null;
	exp.keyGenSpec = null;
	exp.keysize = 0;
	exp.diff21 = 0;
	exp.diff32 = 0;
	exp.diff43 = 0;
	exp.diff54 = 0;
	exp.diff65 = 0;
	exp.diff61 = 0;
	exp.diff63 = 0;
	exp.provider = "";
	exp.sign = false;

	testStreamEncryption(exp, provider);
      }
      catch (Exception e) {
	_log.error("Unable to encrypt", e);
	printResults(exp, e.toString());
      }
      return;
    }

//    for (int j = 0 ; j < _cipherSpecs.length ; j++) {
      for (int k = 0 ; k < _keyGeneratorSpecs.length ; k++) {
	for (int l = 0 ; l < _modeSpecs.length ; l++) {
	  for (int m = 0 ; m < _paddingSpecs.length ; m++) {
	    try {
	      //String transform = _cipherSpec[k] + "/"
	      String transform = _keyGeneratorSpecs[k] + "/"
		+ _modeSpecs[l] + "/" + _paddingSpecs[m];

	      // Unsupported modes
	      if (transform.equals("AES/NONE/NoPadding")
		  || transform.equals("AES/PCBC/NoPadding")
		  || transform.equals("DES/NONE/NoPadding")
		) {
		continue;
	      }
	      for (int i = 0 ; i < 1 ; i++) {
		exp.experimentNumber++;
		exp.cipherSpec = transform;
		exp.keyGenSpec = _keyGeneratorSpecs[k];
		exp.keysize = keysize;
		exp.diff21 = 0;
		exp.diff32 = 0;
		exp.diff43 = 0;
		exp.diff54 = 0;
		exp.diff65 = 0;
		exp.diff61 = 0;
		exp.diff63 = 0;
		exp.provider = "";
		exp.sign = _signStream;

		testStreamEncryption(exp, provider);
	      }
	    }
	    catch (Exception e) {
	      _log.error("Unable to encrypt", e);
	      printResults(exp, e.toString());
	    }
	  }
	}
      }
//    }
  }

  private Hashtable ciphers = new Hashtable();

  private void testStreamEncryption(Experiment exp, Provider provider)
    throws Exception {

    Cipher ci = null;
    long date1 = 0;
    long date2 = 0;
    long date3 = 0;

    List objectList = createObjects(exp.streamSize);

    if (exp.keysize > 0) {
      if (exp.keyGenSpec.equals("DES") || exp.cipherSpec.equals("DES")) {
	// Key length must 56
	exp.keysize = 56;
      }
      else if (exp.keyGenSpec.equals("DESede")
	       || exp.cipherSpec.equals("DESede")) {
	// Key length must be 112 or 168
	exp.keysize = 112;
      }

      /*
	_log.info("Test stream encryption. Cipher=" + exp.cipherSpec
	+ " - keygen=" + exp.keyGenSpec
	+ " - keylength=" + exp.keysize
	+ " - stream size=" + exp.streamSize);
      */

      date1 = new Date().getTime();

      SecretKey sk = null;
      SecureRandom random = new SecureRandom();
      KeyGenerator kg = KeyGenerator.getInstance(exp.keyGenSpec);
      kg.init(exp.keysize, random);
      sk = kg.generateKey();

      date2 = new Date().getTime();
      exp.diff21 = date2 - date1;

      String key = exp.cipherSpec + "/" + (provider == null ? "" : provider.toString());
      ci = (Cipher) ciphers.get(key);
      if (ci == null) {
	if (provider == null) {
	  ci=Cipher.getInstance(exp.cipherSpec);
	}
	else {
	  ci=Cipher.getInstance(exp.cipherSpec, provider);
	}
	ciphers.put(key, ci);
      }
      ci.init(Cipher.ENCRYPT_MODE, sk);

      exp.provider = ci.getProvider().toString();
    }
    else {
      date1 = new Date().getTime();
      date2 = date1;
    }

    date3 = new Date().getTime();
    exp.diff32 = date3 - date2;

    String fileName = System.getProperty("org.cougaar.workspace")
      + File.separator + "stream" + File.separator +
      "encryptedStream" + exp.experimentNumber + ".dat";
    FileOutputStream fos = new FileOutputStream(fileName);
    CipherOutputStream cos = null;
    DigestOutputStream dos = null;
    if (exp.keysize > 0) {
      cos = new CipherOutputStream(fos, ci);
      if (exp.sign) {
	MessageDigest md = MessageDigest.getInstance("SHA");
	dos = new DigestOutputStream(cos, md);
      }
    }
     
    long date4 = new Date().getTime();
    exp.diff43 = date4 - date3;

    if (exp.keysize > 0) {
      if (exp.sign) {
	dumpData3(dos, objectList);
      }
      else {
	dumpData3(cos, objectList);
      }
    }
    else {
      dumpData3(fos, objectList);
    }
    long date5 = new Date().getTime();
    exp.diff54 = date5 - date4;

    if (exp.keysize > 0) {
      if (exp.sign) {
	MessageDigest md = dos.getMessageDigest();
	byte digest[] = md.digest();
	dos.close();
      }
      else {
	cos.close();
      }
    }
    else {
      fos.close();
    }
    long date6 = new Date().getTime();
    exp.diff65 = date6 - date5;
    exp.diff61 = date6 - date1;
    exp.diff63 = date6 - date3;

    /*
    _log.info("date2 - date1=" + (exp.diff21));
    _log.info("date3 - date2=" + (exp.diff32));
    _log.info("date4 - date3=" + (exp.diff43));
    _log.info("date5 - date4=" + (exp.diff54));
    _log.info("date6 - date5=" + (exp.diff65));
    _log.info("date6 - date1=" + (exp.diff61));
    */

    printResults(exp, "");
  }

  private void printResults(Experiment exp, String msg) {
    _log.debug(exp.experimentNumber
	       + ", " + exp.streamSize
	       + ", " + exp.keysize
	       + ", " + exp.cipherSpec
	       + ", " + exp.keyGenSpec
	       + ", " + exp.provider
	       + ", " + (exp.diff21)
	       + ", " + (exp.diff32)
	       + ", " + (exp.diff43)
	       + ", " + (exp.diff54)
	       + ", " + (exp.diff65)
	       + ", " + (exp.diff61)
	       + " * " + (exp.diff63)
	       + " * " + (exp.sign)
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
    public long diff63;

    public int streamSize;

    public boolean sign;
    public String provider;
  }

  private void dumpData(OutputStream os, int bufferLength, int streamLength)
    throws IOException {
    byte[] data = new byte[bufferLength];
    for (int i = 0 ; i < (1 + streamLength / bufferLength) ; i++) {
      os.write(data);
    }
  }


  private void dumpData2(OutputStream os, int bufferLength, int streamLength)
    throws IOException {

    ObjectOutputStream oos = new ObjectOutputStream(os);
    String string = "asdfkjasd;fjjkalsdfjasdasdfkajsdfkljsadf;lkjasd;lfjasdlkfj;lasd";

    for (int i = 0 ; i < 13 * (1 + streamLength / (string.length())) ; i++) {
      oos.writeObject(string);
    }
  }
  private void dumpData3(OutputStream os, Object o)
    throws IOException {

    ObjectOutputStream oos = new ObjectOutputStream(os);
    oos.writeObject(o);
  }

  private static class MyObject
    implements Serializable
  {
    // The content is not very relevant. It's used to store some random
    // blackboard objects.

    public MyObject (int a, String s) {
      _a = a;
      _s = s;
    }

    private int _a;
    private String _s;
  }


  protected void loadCryptoProviders(ClassLoader cl)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Loading cryptographic providers");
    }
    String config_path = System.getProperty("org.cougaar.config.path");
    /*
    FileFinder fileFinder = FileFinderImpl.getInstance(config_path);
    File file = fileFinder.locateFile("cryptoprovider.conf");
    */

    StringBuffer configfile=new StringBuffer();
    String configproviderpath=
      System.getProperty("org.cougaar.core.security.crypto.cryptoProvidersFile");
    String sep = File.separator;
    if((configproviderpath==null)||(configproviderpath=="")) {
      configproviderpath=System.getProperty("org.cougaar.install.path");    
      if((configproviderpath!=null)||(configproviderpath!="")) {
	configfile.append(configproviderpath);
	configfile.append(sep+"configs"+sep+"security"+sep+"cryptoprovider.conf");
      }
      else {
	System.err.println("Error loading cryptographic providers: org.cougaar.install.path not set");
	return;
      }
    }
    else {
      configfile.append(configproviderpath);
    }
    File file=new File(configfile.toString());

    if(file == null || !file.exists()) {
      _log.warn("Cannot find Cryptographic Provider Configuration file");
      return;
    }
    try {
      FileReader filereader=new FileReader(file);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();
      int index=0;
      String providerclassname="";
      while((linedata=buffreader.readLine())!=null) {
	linedata.trim();
	if(linedata.startsWith("#")) {
	  continue;
	}
	if(linedata.startsWith("security.provider")) {
	  index=linedata.indexOf('=');
	  if(index!=-1) {
	    providerclassname=linedata.substring(index+1);
	    if (_log.isDebugEnabled()) {
	      _log.debug("Loading provider " + providerclassname);
	    }
	    try {
	      if (_log.isDebugEnabled()) {
		_log.debug("Loading " + providerclassname
			      + " with " + cl.toString());
	      }
	      Class c = Class.forName(providerclassname, true, cl);
	      Object o = c.newInstance();
	      if (o instanceof java.security.Provider) {
		Security.addProvider((java.security.Provider) o);
	      }
	    } 
	    catch(Exception e) {
	      _log.warn("Error loading security provider (" + e + ")"); 
	    }
	  }
	}
      }
    }
    catch(FileNotFoundException fnotfoundexp) {
      _log.warn("cryptographic provider configuration file not found");
    }
    catch(IOException ioexp) {
      _log.warn("Cannot read cryptographic provider configuration file", ioexp);
    }
    if (_log.isDebugEnabled()) {
      //printProviderProperties();
    }
  }

  public void printProviderProperties() {
    Provider[] pv = Security.getProviders();
    for (int i = 0 ; i < pv.length ; i++) {
      _log.debug("Provider[" + i + "]: "
		    + pv[i].getName() + " - Version: " + pv[i].getVersion());
      _log.debug(pv[i].getInfo());
      // List properties
      String[] properties = new String[1];
      properties = (String[]) pv[i].keySet().toArray(properties);
      Arrays.sort(properties);
      for (int j = 0 ; j < properties.length ; j++) {
	String key, value;
	key = (String) properties[j];
	value = pv[i].getProperty(key);
	_log.debug("Key: " + key + " - Value: " + value);
      }
    }
  }

}
