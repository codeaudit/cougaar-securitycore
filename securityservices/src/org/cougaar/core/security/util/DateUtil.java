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
