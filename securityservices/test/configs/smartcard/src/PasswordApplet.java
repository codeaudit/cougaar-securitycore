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
package org.cougaar.javacard.demo;

import javacard.framework.*;
import javacard.security.*;

public class PasswordApplet extends javacard.framework.Applet {
  
  // Applet instruction class
  final static byte PASSWORD_APPLET_CLA = (byte) 0x44;
  
  // Instruction set for PasswordApplet
  final static byte SET_PASSWORD = (byte) 0x10;
  final static byte GET_PASSWORD = (byte) 0x20;
  final static byte SELECT = (byte) 0xA4;
  
  byte _password[];
  byte _pwdLen;

  private PasswordApplet(byte buffer[], short offset, byte length) {
    // try to allocate all needed space in the constructor
    _password = new byte[127];
    _pwdLen   = (byte) 0;
    
    if (buffer[(byte)offset] == (byte) 0) {
      register();
    } else {
      register(buffer, (short)(offset + 1), buffer[offset]);
    } // end of else
  }

  /**
   * Create an instance of this application
   */
  public static void install(byte buffer[], short offset, byte length) {
    PasswordApplet pa = new PasswordApplet(buffer, offset, length);
  }

  /**
   * Called when the applet is selected
   */
  public boolean select() {
    return true;
  }

  /**
   * Dispatch the application requests
   */
  public void process(APDU apdu) throws ISOException {
    byte buffer[] = apdu.getBuffer();
    
    if (selectingApplet()) {
      ISOException.throwIt(ISO7816.SW_NO_ERROR);
    } // end of if (selectingApplet())

    if (buffer[ISO7816.OFFSET_CLA] != PASSWORD_APPLET_CLA) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    } // end of if (buffer[ISO7816.OFFSET_CLA != PASSWORD_APPLET_CLA)
    
    switch (buffer[ISO7816.OFFSET_INS]) {
    case SET_PASSWORD:
      setPassword(apdu);
      break;
      
    case GET_PASSWORD:
      getPassword(apdu);
      break;
      
    default:
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    } // end of switch (buffer[ISO7816.OFFSET_INS])
  }

  private void setPassword(APDU apdu) {
    byte buffer[] = apdu.getBuffer();
    _pwdLen = (byte) apdu.setIncomingAndReceive();
    byte index;

    for (index = 0; index < _pwdLen; index++) {
      _password[index] = buffer[(byte)(ISO7816.OFFSET_CDATA + index)];
    }
  }

  private void getPassword(APDU apdu) {
    byte buffer[] = apdu.getBuffer();

    byte numBytes = buffer[ISO7816.OFFSET_LC];

    if (numBytes <= (byte) (_pwdLen + 1)) {
      ISOException.throwIt((short)(0x6200 + (short)(_pwdLen + 1)));
    }

    apdu.setOutgoing();
    apdu.setOutgoingLength(numBytes);
		
    byte index;
    
    buffer[0] = _pwdLen;

    for (index = 0; index < _pwdLen; index++) {
      buffer[(byte)(index + 1)] = _password[index];
    }

    index++;

    while (index < numBytes) {
      buffer[index++] = (byte) 0;
    } // end of while (index < numBytes)

    apdu.sendBytes((short)0,(short)numBytes);
  }
}

