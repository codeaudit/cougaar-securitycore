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
