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

package org.cougaar.core.security.crlextension.x509.extensions;

import java.io.IOException;
import java.util.Iterator;

import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.GeneralNames;

public class CougaarGeneralNames extends GeneralNames{

  public  CougaarGeneralNames() {
     super();
  }

  public  CougaarGeneralNames(DerValue dervalue) throws IOException {
    super(dervalue);
  }

  public void encode(DerOutputStream deroutputstream)
     throws IOException {
        if(size() == 0)
            return;
        Iterator it = iterator();
        DerOutputStream deroutputstream1 = new DerOutputStream();
        while(it.hasNext()) 
        {
            Object obj = it.next();
            if(!(obj instanceof GeneralNameInterface))
                throw new IOException("Element in GeneralNames not of type GeneralName.");
            GeneralNameInterface generalnameinterface = (GeneralNameInterface)obj;
            DerOutputStream deroutputstream2 = new DerOutputStream();
            generalnameinterface.encode(deroutputstream2);
            int i = generalnameinterface.getType();
            if(i == 0 || i == 3 || i == 4 || i == 5)
                deroutputstream1.writeImplicit(DerValue.createTag((byte)-128, true, (byte)i), deroutputstream2);
            else
                deroutputstream1.writeImplicit(DerValue.createTag((byte)-128, false, (byte)i), deroutputstream2);
        }
        deroutputstream.write((byte)48, deroutputstream1);
    }
}
