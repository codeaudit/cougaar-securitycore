package com.nai.security.test;

import java.util.*;
import java.math.BigInteger;

public class TestHashtable
{
  public static void main(String args[]) {
    System.out.println("Test hashtable");

    Hashtable t = new Hashtable();

    HashKey o1 = new HashKey(new BigInteger("1"), "test");
    HashKey o2 = new HashKey(new BigInteger("2"), "test");
    HashKey o3 = new HashKey(new BigInteger("1"), "test");

    System.out.println("Adding o1");
    t.put(o1, "value1");

    //System.out.println("Adding o2");
    //t.put(o2, "value2");

    if (t.containsKey(o2)) {
      System.out.println("Contains o2");
    }
  }
    
}
