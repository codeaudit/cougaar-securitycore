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
package org.cougaar.core.security.test.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.service.DataProtectionKey;
import org.cougaar.core.service.DataProtectionKeyEnvelope;
import org.cougaar.core.service.DataProtectionService;
import org.cougaar.core.service.DataProtectionServiceClient;

public class DataProtectionTest implements DataProtectionServiceClient {
  DataProtectionService dps;
  String agent;
  ArrayList list = new ArrayList();
  ServiceBroker serviceBroker;

  public DataProtectionTest(ServiceBroker serviceBroker, String agent) {
    this.agent = agent;
    this.serviceBroker = serviceBroker;
  }

  public MessageAddress getAgentIdentifier() {
    return MessageAddress.getMessageAddress(agent);
  }

  public Iterator iterator() {
    return list.iterator();
  }

  void init() {
    dps = (DataProtectionService)
      serviceBroker.getService(this,
			       DataProtectionService.class,
			       null);
  }

  public DataProtectionKeyEnvelope testOutput(
    DataProtectionKeyEnvelope env, String of, String inf, boolean append)
  {
    init();
    try {
      DataProtectionKeyEnvelope dpe = env;
      if (dpe == null)
        dpe = new DataProtectionKeyEnvelopeImpl();
      FileInputStream is = new FileInputStream(new File(inf));
      File ffof = new File(of);
      ffof.createNewFile();
      FileOutputStream fos = new FileOutputStream(ffof, append);
      OutputStream os = dps.getOutputStream(dpe, fos);
      byte [] rbytes = new byte[2000];
      int result = 0;
      while (true) {
        result = is.read(rbytes);
        if (result == -1)
          break;
        os.write(rbytes, 0, result);
      }
      //System.out.println("out: " + result + " : " + new String(rbytes));
      is.close();
      os.close();
      return dpe;
    } catch (Exception ex) {
      System.out.println("Exception: " + ex.toString());
      ex.printStackTrace();
    }
    return null;
  }

  public void testInput(DataProtectionKeyEnvelope dpKey, String of, String inf) {
    list.add(dpKey);
    init();
    try {
      FileInputStream fis = new FileInputStream(new File(inf));
      FileOutputStream fos = new FileOutputStream(new File(of));
      InputStream is = dps.getInputStream(dpKey, fis);
      byte [] rbytes = new byte[2000];
      while (true) {
        int result = is.read(rbytes);
        if (result == -1)
          break;
        fos.write(rbytes, 0, result);
      }
      is.close();
      fos.close();
    } catch (Exception ex) {
      //System.out.println("Exception: " + ex.toString());
      ex.printStackTrace();
    }
  }

  public static void main(String [] argv) {
    if (argv.length != 4) {
      System.out.println("Incorrect arguments.");
      System.out.println("  Format: type agent inputfile outputfile");
      System.out.println("  type: -o is generating output stream, -i is input.");
      return;
    }

    try {
      SecurityServiceProvider secProvider = new SecurityServiceProvider();
      ServiceBroker serviceBroker = secProvider.getServiceBroker();
      DataProtectionTest dptest = new DataProtectionTest(serviceBroker, argv[1]);
      if (argv[0].equals("-o"))
        dptest.testOutput(null, argv[3], argv[2], false);
      else if (argv[0].equals("-i"))
        dptest.testInput(null, argv[3], argv[2]);
      else
	System.out.println("Wrong argument:" + argv[0]);
    } catch (Exception ex) {
      System.out.println("Exception: " + ex.toString());
      ex.printStackTrace();
    }
  }

  public DataProtectionKeyEnvelope createEnvelope() {
    return new DataProtectionKeyEnvelopeImpl();
  }

  public class DataProtectionKeyEnvelopeImpl
    implements DataProtectionKeyEnvelope
  {
    DataProtectionKey dpkey;

    public DataProtectionKey getDataProtectionKey() {
      return dpkey;
    }

    public void setDataProtectionKey(DataProtectionKey dpKey) {
      dpkey = dpKey;
    }
  }
}
