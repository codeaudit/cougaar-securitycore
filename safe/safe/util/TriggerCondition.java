/**
 * Last Modified by: $Author: srosset $
 * On: $Date: 2002-05-17 23:18:09 $
 */package safe.util;

import java.io.Serializable;

/**
 * A TriggerCondition represents a conditional statement of the type:
 * if (object of type x with fieldname of y has a value <comparisonType> z)
 * where <comparisonType> could be equal to, less than, greater than,
 * etc. Currently only equal is implemented.
 */
public class TriggerCondition implements Serializable
{
    /**
     * Constructor
     * 
     * @param className         The type of object to monitor
     * @param fieldName         The field of the object to monitor
     * @param value             The desired value of the field
     * @param comparisonType    The type of comparison to perform
     * 
     */
    public TriggerCondition (String className,
                             String fieldName,
                             Serializable value,
                             int comparisonType)
    {
        _className = className;
        _fieldName = fieldName;
        _value = value;
        _comparisonType = comparisonType;
    }

    /**
     * @return the type of object to monitor
     */
    public String getClassName()
    {
        return _className;
    }
    
    /**
     * @return the field of the object to monitor
     */
    public String getFieldName()
    {
        return _fieldName;
    }

    /**
     * @return the desired value of the field
     */
    public Serializable getValue()
    {
        return _value;
    }
    
    /**
     * @return the type of comparison to perform
     */
    public int getComparisonType()
    {
        return _comparisonType;
    }
    
    /**
     * Returns a string representation of the condition of the form
     * "className.fieldName <comparisonTypeSymbol> value"
     */
	public String toString()
	{
		String conditionStr = _className + "." + _fieldName + " ";
		String comparisonTypeStr;
		switch (_comparisonType) {
		case EQUAL: comparisonTypeStr = "==";
					break;
		default: comparisonTypeStr = "UNKNOWN";
				 break;
		}
		conditionStr += comparisonTypeStr + " " + _value;
		
		return conditionStr;							  
	}
	
    public static final int EQUAL = 1;
    
    private String _className;
    private String _fieldName;
    private Serializable _value;
    private int _comparisonType;                                  
}
