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
package org.cougaar.core.security.policy;

public class CryptoPolicyBean {
    //protected String senderName;
    protected String targetName;
    protected String secureMethod;
    protected String symmetricAlgorithm;
    protected String asymmetricAlgorithm;
    protected String signingAlgorithm;
    protected String messageSecurityManager;
    protected String providerName;

    public CryptoPolicyBean(){
    }

    public String toString() {
        String str = new String();
        str = //"senderName is: " + senderName + "\n" +
            "targetName is: " + targetName + "\n" +
            "secureMethod is: " + secureMethod + "\n" +
            "symmetricAlgorithm is: " + symmetricAlgorithm + "\n" +
            "asymmetricAlgorithm is: " + asymmetricAlgorithm + "\n" +
            "signingAlgorithm is: " + signingAlgorithm + "\n" +
            "messageSecurityManager is: " + messageSecurityManager + "\n" +
            "providerName is: " + providerName + "\n";

        return str;
    }

   // public String getSenderName(){
   //     return senderName;
   // }

   // public void setSenderName(String senderName){
   //     this.senderName = senderName;
   // }

    public String getTargetName(){
        return targetName;
    }

    public void setTargetName(String targetName){
        this.targetName = targetName;        
    }

    public String getSecureMethod(){
        return secureMethod;
    }

    public void setSecureMethod(String secureMethod){
        this.secureMethod = secureMethod;
    }

    public String getSymmetricAlgorithm(){
        return symmetricAlgorithm;
    }

    public void setSymmetricAlgorithm(String algorithm){
        this.symmetricAlgorithm = algorithm;
    }

    public String getAsymmetricAlgorithm(){
        return asymmetricAlgorithm;
    }

    public void setAsymmetricAlgorithm(String algorithm){
        this.asymmetricAlgorithm = algorithm;
    }

    public String getSigningAlgorithm(){
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(String algorithm){
        this.signingAlgorithm = algorithm;
    }

    public String getMessageSecurityManager(){
        return messageSecurityManager;
    }

    public void setMessageSecurityManager(String messageSecurityManager){
        this.messageSecurityManager = messageSecurityManager;
    }

    public String getProviderName(){
        return providerName; 
    }

    public void setProviderName(String provider){
        providerName = provider;
    }


}
