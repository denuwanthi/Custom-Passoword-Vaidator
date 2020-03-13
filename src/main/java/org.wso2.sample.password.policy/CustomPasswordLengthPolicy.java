package org.wso2.sample.password.policy;

import org.wso2.carbon.identity.mgt.policy.AbstractPasswordPolicyEnforcer;

import java.util.Map;

public class CustomPasswordLengthPolicy extends AbstractPasswordPolicyEnforcer {

    private int MIN_LENGTH = 6;
    private int MAX_LENGTH = 10;

    /**
     * Required initializations to get the configuration values from file.
     */
    @Override
    public void init(Map<String, String> params) {

        /*
         *  Initialize the configuration with the parameters defined in config file.
         *  Eg.
         *  In the config file if you specify as follows.
         *  Password.policy.extensions.1.min.length=6
         *  Get the value from the map as shown below using key "min.length".
         */
        if (!(params == null || params.isEmpty())) {
            MIN_LENGTH = Integer.parseInt(params.get("min.length"));
            MAX_LENGTH = Integer.parseInt(params.get("max.length"));
        }
    }

    /**
     * Policy enforcing method.
     *
     * @param - the first parameter assumed to be the password. The order of the parameters
     *          are implementation dependent.
     */
    @Override
    public boolean enforce(Object... args) {

        // If null input pass through.
        if (args != null) {

            String password = args[0].toString();
            if (password.length() < MIN_LENGTH) {
                errorMessage = "Password must have at least " + MIN_LENGTH + " characters";
                return false;
            } else if (password.length() > MAX_LENGTH) {
                errorMessage = "Password cannot have more than " + MAX_LENGTH + " characters";
                return false;
            } else {
                return true;
            }
        } else {
            return true;
        }
    }
}
