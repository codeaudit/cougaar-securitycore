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


package org.cougaar.core.security.securebootstrap;

import java.security.Principal;
import java.util.Date;


public class BootstrapEvent {
  public String classification=null;
  public Date detecttime=null;
  public Principal [] principals=null;
  public String subjectStackTrace=null;
 
  public BootstrapEvent(String type,
			Date detectTime,
			Principal [] subjectsprincipal,
			String stackinfo) {
    classification=type;
    detecttime=detectTime;
    principals=subjectsprincipal;
    subjectStackTrace=stackinfo;
   
    
  }
  public BootstrapEvent(){
  }
  public String toString() {
    StringBuffer buffer=new StringBuffer();
    buffer.append("Type :"+classification +"\n");
    if(detecttime!=null)
      buffer.append("Time :"+detecttime.toString() +"\n"); 
    if(principals!=null){
      buffer.append("Principals  :"+principals.toString() +"\n"); 
    }
    buffer.append("Stack Trace :"+subjectStackTrace +"\n");
    return buffer.toString();
  }
			
}
