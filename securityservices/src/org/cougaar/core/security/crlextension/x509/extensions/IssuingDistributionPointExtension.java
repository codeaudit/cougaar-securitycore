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
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.util.Enumeration;

import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AttributeNameEnumeration;
import sun.security.x509.CertAttrSet;
import sun.security.x509.Extension;



public class IssuingDistributionPointExtension extends Extension
  implements CertAttrSet
{

  private void encodeThis()
    throws IOException
  {
       
    DerOutputStream deroutputstream = new DerOutputStream();
    DerOutputStream deroutputstream1 = new DerOutputStream();
    DerOutputStream deroutputstream2 = new DerOutputStream();
    deroutputstream2.putBoolean(onlyusercert);
    deroutputstream1.write(DerValue.createTag((byte)-128,true,(byte)1), deroutputstream2);
    DerOutputStream deroutputstream3 = new DerOutputStream();
    deroutputstream3.putBoolean(onlycacert);
    deroutputstream1.write(DerValue.createTag((byte)-128,true,(byte)2), deroutputstream3);

    DerOutputStream deroutputstream4 = new DerOutputStream();
    deroutputstream4.putBoolean(indirectCRL);
    deroutputstream1.write(DerValue.createTag((byte)-128,true,(byte)4), deroutputstream4);

      
    deroutputstream.write((byte)48, deroutputstream1);
    super.extensionValue = deroutputstream.toByteArray();
  }

  public IssuingDistributionPointExtension(boolean usercert, boolean cacert, boolean  indirectcrl)
    throws IOException
  {
    onlyusercert=usercert;
    onlycacert=cacert;
    indirectCRL=indirectcrl;
    super.extensionId =new ObjectIdentifier(issungDistributionPointOID);
    super.critical = true;
    encodeThis();
  }
 
  public IssuingDistributionPointExtension(Boolean boolean1, Object obj)
    throws IOException
  {

    onlyusercert=false;;
    onlycacert=false;
    indirectCRL = false;

    super.extensionId =new ObjectIdentifier(issungDistributionPointOID);
    super.critical = boolean1.booleanValue();
    if(!(obj instanceof byte[]))
      throw new IOException("Illegal argument type");
    int i = Array.getLength(obj);
    byte abyte0[] = new byte[i];
    System.arraycopy(obj, 0, abyte0, 0, i);
    super.extensionValue = abyte0;
    DerValue dervalue = new DerValue(abyte0);
    if(dervalue.tag != 48)
      throw new IOException("Sequence tag missing for Issuing Distribution Point .");

    DerInputStream derinputstream = dervalue.data;
    dervalue=derinputstream.getDerValue();

    if(dervalue.isContextSpecific((byte)1)) {
      if(dervalue.isConstructed()&&dervalue.isContextSpecific()) {
	DerValue value1=dervalue.data.getDerValue();
	onlyusercert=value1.getBoolean();
	dervalue=derinputstream.getDerValue();
      }
      else {
	throw new IOException("Unable to create  OnlyUserCertificate value  in  Issuing Distribution Point .");
      }
    }
   
    if(dervalue.isContextSpecific((byte)2)) {
      if(dervalue.isConstructed()&&dervalue.isContextSpecific()) {
	DerValue value1=dervalue.data.getDerValue();
	onlycacert=value1.getBoolean();
	dervalue=derinputstream.getDerValue();
      }
      else {
	throw new IOException("Unable to create  OnlyCACertificate value  in  Issuing Distribution Point .");
      }
    }
   
    if(dervalue.isContextSpecific((byte)4)) {
      if(dervalue.isConstructed()&&dervalue.isContextSpecific()) {
	DerValue value1=dervalue.data.getDerValue();
	indirectCRL=value1.getBoolean();
      }
      else {
	throw new IOException("Unable to create  indirectCRL  value  in  Issuing Distribution Point .");
      }
    }
    else {
      throw new IOException("Invalid encoding of IssuingDistrubution pt");
    }
    encodeThis();
	
  }

  public String toString()
  {
    StringBuffer buffer=new StringBuffer();  
    String s = super.toString() + "Issuing Distribution point [\n";
    buffer.append(s);
    buffer.append("onlyusercert :"+onlyusercert +"\n");
    buffer.append("onlycacert : "+onlycacert +"\n");
    buffer.append("indirectCRL :"+indirectCRL +"\n");      
    return buffer.toString() + "]\n";
  }

  public void decode(InputStream inputstream)
    throws IOException
  {
    throw new IOException("Method not to be called directly.");
  }

  public void encode(OutputStream outputstream)
    throws IOException
  {
    DerOutputStream deroutputstream = new DerOutputStream();
    if(super.extensionValue == null)
      {
	super.extensionId = new ObjectIdentifier(issungDistributionPointOID);
	super.critical = true;
	encodeThis();
      }
    super.encode(deroutputstream);
    outputstream.write(deroutputstream.toByteArray());
  }

  public void set(String s, Object obj)
    throws IOException
  {
    if(s.equalsIgnoreCase(ONLY_CONTAINS_USER_CERT)) {
      if(!(obj instanceof Boolean))
	throw new IOException("Attribute value should be of type Boolean.");
      onlyusercert = ((Boolean)obj).booleanValue();
    } 
    else if(s.equalsIgnoreCase(ONLY_CONTAINS_CA_CERT)) {
      if(!(obj instanceof Boolean))
	throw new IOException("Attribute value should be of type Boolean.");
      onlycacert = ((Boolean)obj).booleanValue();
    } 
    else if(s.equalsIgnoreCase(INDIRECT_CRL)) {
      if(!(obj instanceof Boolean))
	throw new IOException("Attribute value should be of type Boolean.");
      indirectCRL = ((Boolean)obj).booleanValue();
    } 
    else {
      throw new IOException("Attribute name not recognized by Issuing Distribution point.");
    }
    encodeThis();
  }

  public Object get(String s)
    throws IOException
  {
    if(s.equalsIgnoreCase(ONLY_CONTAINS_USER_CERT))
      return new Boolean(onlyusercert);
    if(s.equalsIgnoreCase(ONLY_CONTAINS_CA_CERT))
      return new Boolean(onlycacert);
    if(s.equalsIgnoreCase(INDIRECT_CRL))
      return new Boolean(indirectCRL); 
    else
      throw new IOException("Attribute name not recognized by CertAttrSet:Issuing Distribution pt.");
  }

  public void delete(String s)
    throws IOException
  {
    if(s.equalsIgnoreCase(ONLY_CONTAINS_USER_CERT))
      onlyusercert=false;
    if(s.equalsIgnoreCase(ONLY_CONTAINS_CA_CERT))
      onlycacert=false;
    if(s.equalsIgnoreCase(INDIRECT_CRL))
      indirectCRL=false; 
    else
      throw new IOException("Attribute name not recognized by Issuing Distribution point .");
    encodeThis();
  }

  public Enumeration getElements()
  {
    AttributeNameEnumeration attributenameenumeration = new AttributeNameEnumeration();
    attributenameenumeration.addElement(ONLY_CONTAINS_USER_CERT);
    attributenameenumeration.addElement(ONLY_CONTAINS_CA_CERT);
    attributenameenumeration.addElement(INDIRECT_CRL);
    return attributenameenumeration.elements();
  }

  public String getName()
  {
    return "IssuingDistibutionPoint";
  }


  public static final String IDENT = "x509.info.extensions.issuingDistributionPoint";
  public final String issungDistributionPointOID="2.5.29.28";
  public static final String NAME = "IssuingDistributionPoint";
  public static final String DISTRIBUTION_POINT = "DISTIBUTION_POINT";
  public static final String ONLY_CONTAINS_USER_CERT ="onlyContainsUserCerts";
  public static final String  ONLY_CONTAINS_CA_CERT = "onlyContainsCACerts";
  public static final String  ONLY_SOME_REASON = "onlySomeReason";
  public static final String  INDIRECT_CRL = "indirectCRL";
  private static final byte TAG_DP = 0;
  private static final byte TAG_ONLYUSERCERT = 1;
  private static final byte TAG_ONLYCACERT = 2;
  private static final byte TAG_SOMEREASON = 3;
  private static final byte TAG_INDIRECRL = 4;
  private boolean onlyusercert=false; 
  private boolean onlycacert=false;
  private boolean indirectCRL=false;

}





