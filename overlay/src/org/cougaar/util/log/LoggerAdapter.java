/*
 * <copyright>
 *  Copyright 1997-2003 BBNT Solutions, LLC
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

package org.cougaar.util.log;

/** Standard implementation of all the busy-work of Logger
 **/
public abstract class LoggerAdapter
  implements Logger
{

  public abstract boolean isEnabledFor(int level);
  public abstract void log(int level, String message, Throwable t);


  public final void log(int level, String message) { log(level,message,null); }

  public final boolean isDetailEnabled() { return isEnabledFor(DETAIL); }
  public final boolean isDebugEnabled()  { return isEnabledFor(DEBUG); }
  public final boolean isInfoEnabled()   { return isEnabledFor(INFO); }
  public final boolean isWarnEnabled()   { return isEnabledFor(WARN); }
  public final boolean isErrorEnabled()  { return isEnabledFor(ERROR); }
  public final boolean isShoutEnabled()  { return isEnabledFor(SHOUT); }
  public final boolean isFatalEnabled()  { return isEnabledFor(FATAL); }

  public final void detail(String message) { log(DETAIL, message, null); }
  public final void detail(String message, Throwable t) { log(DETAIL, message, t); }
  public final void debug(String message) { log(DEBUG, message, null); }
  public final void debug(String message, Throwable t) { log(DEBUG, message, t); }
  public final void info(String message) { log(INFO, message, null); }
  public final void info(String message, Throwable t) { log(INFO, message, t); }
  public final void warn(String message) { log(WARN, message, null); }
  public final void warn(String message, Throwable t) { log(WARN, message, t); }
  public final void error(String message) { log(ERROR, message, null); }
  public final void error(String message, Throwable t) { log(ERROR, message, t); }
  public final void shout(String message) { log(SHOUT, message, null); }
  public final void shout(String message, Throwable t) { log(SHOUT, message, t); }
  public final void fatal(String message) { log(FATAL, message, null); }
  public final void fatal(String message, Throwable t) { log(FATAL, message, t); }
}
