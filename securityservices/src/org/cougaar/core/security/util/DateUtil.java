/*
 * <copyright>
 *  Copyright 1997-2003 Networks Associates Technology, Inc.
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
 */
package org.cougaar.core.security.util;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;



public class DateUtil {


  public static  Date getDateFromUTC( String utc ) {

    // utc is in the form of "20010706080000Z". get year,
    // month, day, hour, minute, and second from the utc
    if(utc==null) {
      return null;
    }
    //System.out.println("Received utc is :"+ utc);
    TimeZone tz = TimeZone.getTimeZone("GMT");
    int year   = Integer.parseInt( utc.substring(  0, 4  ));
    int mon    = Integer.parseInt( utc.substring(  4, 6  ));
    int day    = Integer.parseInt( utc.substring(  6, 8  ));
    int hour   = Integer.parseInt( utc.substring(  8, 10 ));
    int minute = Integer.parseInt( utc.substring( 10, 12 ));
    int second = Integer.parseInt( utc.substring( 12, 14 ));

    Calendar utcTime = Calendar.getInstance(tz);
    // set calendar to the time
    utcTime.set( year, mon-1 , day, hour, minute, second );
    //  System.out.println("Received Date Object is :"+ utcTime.getTime().toString());
    return utcTime.getTime();
  }

  public static String getCurrentUTC() {
    
    TimeZone  GMT = TimeZone.getTimeZone("GMT");
    Calendar cal=Calendar.getInstance();
    cal.setTimeZone(GMT);
    SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
    formatter.setTimeZone(GMT);
    Date current =cal.getTime();
    return  formatter.format(current);
  }

}
