package org.cougaar.core.security.monitoring.publisher;

import org.cougaar.core.security.monitoring.event.FailureEvent;
import java.util.List;

/**
 * Interface for the different event publishers.
 */
public interface EventPublisher {
  
  /**
   * Publish a list of failure events
   *
   * @events a List of failure events to publish
   */
  public void publishEvents(List events);

  /**
   * Publish a failure event
   *
   * @event the failure event to publish
   */  
  public void publishEvent(FailureEvent event);
}