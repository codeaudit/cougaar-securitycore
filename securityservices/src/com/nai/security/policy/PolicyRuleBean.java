package com.nai.security.policy;

/**
 * A rule bean specifically used to denote a policy rule.
 */
public class PolicyRuleBean {
    /**
     * The name of this rule  
     */
    protected String name;        

    /**
     * The key for this rule is either should be an unique identifier or the 
     * String "DEFAULT" to handle any default cases.
     */
    protected String key;        
    
    /**
     * A value to use in comparison
     */
    protected Object value;      

    /**
     * Blank constructor
     */
    public PolicyRuleBean() {   }

    /**
     * Default constructor for creating  a new persistent rule
     */
    public PolicyRuleBean(String name, String key, Object value)
    {
	this.name = name;
	this.key = key;
	this.value = value;
    }

    public String getName(){
        return name;
    }

    public void setName(String name){
        this.name = name;
    }

    public String getKey(){
        return key;
    }

    public void setKey(String key){
        this.key = key;
    }

    public Object getValue(){
        return value;
    }

    public void setValue(Object value){
        this.value = value;
    }

    public String toString(){
	StringBuffer buff = new StringBuffer("[PolicyRuleBean ");
	buff.append(name).append("(");
	buff.append((key == null)? "DEFAULT": key).append(") = ");
	buff.append(value).append(" ]");
        return buff.toString();
    }

}







