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

    public void setTargetName(String targeName){
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
