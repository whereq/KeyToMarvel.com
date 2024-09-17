package com.whereq.keycloak.wechat;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * Configuration class for the WeChat Identity Provider, extending {@link OIDCIdentityProviderConfig}.
 * It manages specific configuration settings related to WeChat authentication such as customized login URLs
 * for PC, and secondary client IDs for different environments (e.g., WeChat MP client).
 *
 * This class allows setting and getting of the custom login URL for PC, as well as secondary client IDs used for
 * mobile web-based authentication scenarios (WMP).
 *
 * <p>
 * Example usage:
 * <pre>
 *     WeChatIdentityProviderConfig config = new WeChatIdentityProviderConfig();
 *     config.setCustomizedLoginUrlForPc("https://custom-wechat-login-url.com");
 * </pre>
 * </p>
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatIdentityProviderConfig extends OIDCIdentityProviderConfig {

    protected static final Logger logger = Logger.getLogger(WeChatIdentityProviderConfig.class);
    /**
     * Default constructor.
     * Initializes an empty configuration instance for WeChat Identity Provider.
     */
    public WeChatIdentityProviderConfig() {
    }

    /**
     * Constructor that initializes the WeChat identity provider configuration using an {@link IdentityProviderModel}.
     *
     * @param model IdentityProviderModel object representing the current identity provider configuration.
     */
    public WeChatIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    /**
     * Sets a customized login URL for PC-specific WeChat login flow.
     * This can be useful for customizing the login flow for WeChat users on desktop environments.
     *
     * @param customizedLoginUrlForPc The custom login URL to use for WeChat authentication on PC.
     */
    public void setCustomizedLoginUrlForPc(String customizedLoginUrlForPc) {
        logger.info("Setting customized login URL for PC: " + customizedLoginUrlForPc);
        this.getConfig().put(WeChatIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC, customizedLoginUrlForPc);
    }

    /**
     * Retrieves the customized login URL for WeChat PC-based login flow.
     * This is used to direct users in a desktop environment to a custom WeChat login page.
     *
     * @return The custom login URL for PC, or null if none is set.
     */
    public String getCustomizedLoginUrlForPc() {
        String customizedLoginUrlForPc = this.getConfig().get(WeChatIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC);
        logger.info("Retrieved customized login URL for PC: " + customizedLoginUrlForPc);
        return customizedLoginUrlForPc;
    }

    /**
     * Sets a secondary client ID (clientId2) to use for WeChat OAuth2 requests.
     * This can be used when the application needs to handle multiple client credentials for WeChat.
     *
     * @param clientId2 The secondary client ID for WeChat OAuth2 authentication.
     */
    public void setClientId2(String clientId2) {
        logger.info("Setting secondary client ID (clientId2): " + clientId2);
        this.getConfig().put("clientId2", clientId2);
    }

    /**
     * Sets the WeChat Mini Program (WMP) client ID.
     * This is specifically used for handling authentication via WeChat Mini Programs (WMP) environment.
     *
     * @param clientId The client ID for the WeChat Mini Program.
     */
    public void setWmpClientId(String clientId) {
        logger.info("Setting WeChat Mini Program (WMP) client ID: " + clientId);
        this.getConfig().put("wmpClientId", clientId);
    }
}
