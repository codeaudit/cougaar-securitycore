/**
 * Last Modified by: $Author: srosset $
 * On: $Date: 2002-05-17 23:18:09 $
 */package safe.util;

import org.w3c.dom.Document;
import org.cougaar.util.ConfigFinder;

/**
 * This class is used by KPAT to read an XML file into a serializable
 * object.
 */
public class XMLFileReader {
	public static Document getDocumentForFile (String filename)
    {
		Document doc = null;
		ConfigFinder configFinder = new ConfigFinder();

		try {
			doc = configFinder.parseXMLConfigFile(filename);
			if (doc == null) {
				System.err.println("XML parser could not handle file " +
								   filename);
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
        
        return doc;
	}
}
