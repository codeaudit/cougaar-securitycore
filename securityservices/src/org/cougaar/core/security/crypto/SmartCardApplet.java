/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
package org.cougaar.core.security.crypto;

import org.cougaar.core.service.LoggingService;

import java.security.SecureRandom;

import com.linuxnet.jpcsc.Card;
import com.linuxnet.jpcsc.Context;
import com.linuxnet.jpcsc.PCSC;
import com.linuxnet.jpcsc.State;

public class SmartCardApplet {
  
  // Applet instruction class
  final static byte PASSWORD_APPLET_CLA = (byte) 0x44;
  
  // Instruction set for PasswordApplet
  final static byte SET_PASSWORD = (byte) 0x10;
  final static byte GET_PASSWORD = (byte) 0x20;

  final static byte[] SELECT_APPLET = { 
    (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x06,
    (byte) 0, (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5 
  };

  final static byte[] SET_PASSWORD_COMMAND = {
    PASSWORD_APPLET_CLA, SET_PASSWORD, 0, 0
  };

  final static byte[] GET_PASSWORD_COMMAND = {
    PASSWORD_APPLET_CLA, GET_PASSWORD, 0, 0, 100
  };

  final static byte[] AID = { (byte) 0, (byte) 1, (byte) 2,
                              (byte) 3, (byte) 4, (byte) 5 };
  
  public static char[] getKeystorePassword(String cardPassword,
                                           LoggingService log) {
    Context ctx  = null;
    Card    card = null;
    
    try {
      ctx = new Context();
      ctx.EstablishContext(PCSC.SCOPE_SYSTEM, null, null);
      String readers[] = ctx.ListReaders();

      if (readers.length == 0) {
        log.debug("Smart card is required and there aren't any readers");
        throw new SmartCardAppletException("There aren't any readers");
      } // end of if (readers.length == 0)
    
      State states[] = new State[readers.length];
      for (int i = 0; i < readers.length; i++) {
        states[i] = new State(readers[i]);
      } // end of for (int i = 0; i < readers.length; i++)
      
      int cardNum = -1;
      do {
        ctx.GetStatusChange(1000, states);
        for (int i = 0; i < states.length; i++) {
          if (states[i].rgbAtr.length > 0) {
            cardNum = i;
            break;
          } // end of if (states[i].rgbAtr.length > 0)
        } // end of for (int i = 0; i < states.length; i++)
        if (cardNum == -1) {
          log.debug("None of the card readers has a card in it. Retrying...");
          try {
            Thread.sleep(1000);
          } catch (InterruptedException e) {
          } // end of try-catch
        } // end of if (cardNum == -1)
      } while (cardNum == -1);
      
      card = ctx.Connect(readers[cardNum], PCSC.SHARE_SHARED, 
                              PCSC.PROTOCOL_T0);
      byte[] answer;
      card.BeginTransaction();
      answer = card.Transmit(SELECT_APPLET, 0, SELECT_APPLET.length);

      // getting the password:
      answer = card.Transmit(GET_PASSWORD_COMMAND, 0, GET_PASSWORD_COMMAND.length);
      if (answer.length <= 2) {
        throw new SmartCardAppletException("Couldn't get a proper answer from the smart card");
      } // end of if (answer.length <= 2)
    
      int len = answer[0];
      if (len != 0) {
        char buf[] = new char[len];
        while (len > 0) {
          buf[len-1] = (char) answer[len];
          len--;
        } // end of while (len > 0)
        return buf;
      } // end of if (len == 0)

      // create a password:
      SecureRandom random = new SecureRandom();
      byte encPass[] = new byte[20];
      random.nextBytes(encPass);
      char pass[] = Base64.encode(encPass);
      
      byte setPwd[] = new byte[SET_PASSWORD_COMMAND.length + pass.length + 1];
      
      System.arraycopy(SET_PASSWORD_COMMAND, 0, setPwd, 0, 
                       SET_PASSWORD_COMMAND.length);
      int off = SET_PASSWORD_COMMAND.length;
      setPwd[off++] = (byte) pass.length;
      for (int i = 0; i < pass.length; i++) {
        setPwd[off++] = (byte) pass[i];
      } // end of for (int i = 0; i < pass.length; i++)
      
      answer = card.Transmit(setPwd, 0, setPwd.length);
      if (answer.length != 2 || 
          answer[0] != (byte) 0x90 || 
          answer[1] != 0x00) {
        throw new SmartCardAppletException("Couldn't set the password into the smart card");
      } // end of if (answer.length != 2 || answer[0] != 0x90 || answer[1] != 0x00)
      return pass;
    } finally {
      if (card != null) {
        card.EndTransaction(PCSC.LEAVE_CARD);
      } // end of if (card != null)
      if (ctx != null) {
        ctx.ReleaseContext();
      } // end of if (ctx != null)
    } // end of finally
    
  } // end of main ()

  public static void printBytes(byte[] buf) {
    int i;
    for (i = 0; i < buf.length; i++) {
      long l = buf[i] & 0xFF;
      String s = Long.toHexString(l);
      if (s.length() == 1) {
        System.out.print('0');
      } // end of if (s.length == 1)
      System.out.print(s);
      System.out.print(' ');
      if ((i & 0x07) == 0x07) {
        System.out.print(' ');
      } // end of if (i & 0x08)
      if ((i & 0x0F) == 0x0F) {
        printString(buf, i - 0x0F, i);
      } // end of if (i & 0x10)
    } // end of for (int i = 0; i < buf.length; i++)

    while ((i & 0x10) != 0x10) {
      System.out.print("   ");
      if ((i & 0x07) == 0x07) {
        System.out.print(' ');
      } // end of if (i & 0x07 == 0x07)
      if ((i & 0x0F) == 0x0F) {
        printString(buf, i - 0x0F, buf.length - 1);
      } // end of if (i & 0x0F == 0x0F)
      i++;
    } 
  }

  public static void printString(byte[] buf, int start, int end) {
    while (start <= end) {
      if (Character.isLetterOrDigit((char) (((char) buf[start]) & 0xFF))) {
        System.out.print((char) buf[start]);
      } else {
        System.out.print('.');
      } // end of else
      start++;
    } // end of while (start <= end)
    System.out.println();
  }
}

