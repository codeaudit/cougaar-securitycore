/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on November 7, 2001, 4:42 PM
 */

package com.nai.security.certauthority;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.net.*;
import java.io.*;
//import java.net.HttpURLConnection.*;

import com.nai.security.policy.NodePolicy;
import com.nai.security.crypto.ConfParser;

public class CAClient {

    private KeyPairGenerator kpg;
    private NodePolicy policy;
    /** Creates new CertGenerator */
    public CAClient() {
        ConfParser confParser = new ConfParser();
        try{
            kpg = KeyPairGenerator.getInstance("RSA");
            
            //get related policies 
            NodePolicy policy = confParser.readNodePolicy();
            
        }catch(Exception e){
            System.out.println("Error: can't start CA client--"+e.getMessage());
        }
    }
    
    public KeyPair makeKeyPair(){
        //generate key pair.
        return kpg.genKeyPair();
    }
    
    public String sendPKCS(String request, String pkcs){
        String reply = "error";
        try{
            URL url = new URL(policy.CA_URL);
            HttpURLConnection huc = (HttpURLConnection)url.openConnection();
            huc.setDoOutput(true);
            PrintWriter out = new PrintWriter(huc.getOutputStream());
            out.println("pkcs=" + URLEncoder.encode(pkcs));
            out.println("dnname=" + URLEncoder.encode(policy.CA_DN));
            out.println("pkcsdata=" + URLEncoder.encode(request));
            out.close();

            BufferedReader in = new BufferedReader(new InputStreamReader(huc.getInputStream()));
            while((reply = in.readLine()) != null)
                reply += reply;
            in.close();
        }catch(Exception e){
            System.err.println("Error: sending PKCS request to CA failed--" + e.getMessage());
        }
        
        return reply;
    }
}
