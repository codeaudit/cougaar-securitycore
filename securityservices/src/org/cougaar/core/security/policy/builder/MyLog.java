/**
 * Last Modified by: $Author: tredmond $
 * On: $Date: 2003-07-02 20:48:17 $
 */

package org.cougaar.core.security.policy.builder;

import org.apache.log4j.Logger;

public class MyLog implements kaos.core.util.Log
{
  public MyLog ()
  {
    _logger = Logger.getLogger("kaos");
  }

  public void logMessage (String message, int level)
  {
    if (level == kaos.core.util.Logger.LEVEL_GENERAL) {
      if (_logger.isInfoEnabled()) {
        _logger.info(message);
      }
    }
    else if (level == kaos.core.util.Logger.LEVEL_MAJOR) {
      if (_logger.isDebugEnabled()) {
        _logger.debug(message);
      }
    }
    else {
      if (_logger.isDebugEnabled()) {
        _logger.debug(message);
      }
    }
  }

  private static Logger _logger;
}
