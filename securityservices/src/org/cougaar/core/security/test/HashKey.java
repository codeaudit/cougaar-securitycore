package org.cougaar.core.security.test;

import java.math.BigInteger;

class HashKey
{
  BigInteger bi;
  String string;
    
  public HashKey(BigInteger bi, String string)
  {
    this.bi = bi;
    this.string = string;
  }

  public int hashCode() {
    return bi.hashCode();
  }    

  public String toString()
  {
    return bi.toString() + " = " + string;
  }

  public boolean equals(java.lang.Object obj) {
    System.out.println("test equality of" + toString() 
		       + " - " + obj.toString());
    if (obj == null) return false;
    if (!(obj instanceof HashKey))
      return false;
    HashKey other =
      (HashKey) obj;
    return (bi.equals(other.bi) && string.equals(other.string));
  }
}
