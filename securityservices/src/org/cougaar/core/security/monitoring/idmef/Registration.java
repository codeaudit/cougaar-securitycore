package org.cougaar.core.security.monitoring.idmef;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.CreateTime;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;

/**
 * Registration subclasses Alert, and is used to distinguish
 * the difference been an Alert message and a Registration message
 * avoiding the need to determine the message type via the AdditionalData
 * object.
 */
public class Registration extends Alert {
    
    public static String TYPE = "sensor-registration";
    /**
     * Creates a message for an analyzer to register its capabilities.
     * Can only be create through IdmefMessageFactory
     */
    Registration( Analyzer analyzer,
                  Source []sources,
                  Target []targets,
                  Classification []capabilities,
                  AdditionalData []data ){
        super( analyzer, 
               new CreateTime(), 
               null,  // detection time
               null,  // don't think we need AnalyzerTime
               sources, // sources
               targets, // targets
               capabilities,
               null,    // assessment 
               data, 
               null );  // ident 
    }
}
