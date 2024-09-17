package com.whereq.keycloak.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * WeChatIdentityProviderFactory handles the creation of the WeChat Identity Provider
 * for Keycloak, enabling users to log in using their WeChat credentials.
 * This class provides configuration properties specific to WeChat integration,
 * including support for WeChat Official Accounts, Open Platform, and Mini Programs.
 *
 * This class extends {@link AbstractIdentityProviderFactory} and implements
 * {@link SocialIdentityProviderFactory}, facilitating the social login functionality.
 *
 * @see WeChatIdentityProvider
 * @see WeChatIdentityProviderConfig
 * @see SocialIdentityProviderFactory
 * @see AbstractIdentityProviderFactory
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatIdentityProviderFactory extends
        AbstractIdentityProviderFactory<WeChatIdentityProvider> implements
        SocialIdentityProviderFactory<WeChatIdentityProvider> {

    public static final String PROVIDER_ID = "wechat";

    /**
     * Returns the name of the identity provider, in this case, "WeChat".
     *
     * @return the name of the provider, "WeChat"
     */
    @Override
    public String getName() {
        return "WeChat";
    }

    /**
     * Creates a new instance of {@link WeChatIdentityProvider} using the session and model provided.
     * This is the method responsible for instantiating the identity provider class.
     *
     * @param session the current {@link KeycloakSession}
     * @param model the {@link IdentityProviderModel} containing configuration details
     * @return a new {@link WeChatIdentityProvider} instance
     */
    @Override
    public WeChatIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new WeChatIdentityProvider(session, new WeChatIdentityProviderConfig(model));
    }

    /**
     * Creates an instance of {@link OAuth2IdentityProviderConfig}, which holds
     * the configuration details specific to the OAuth2 protocol for the WeChat provider.
     *
     * @return a new {@link OAuth2IdentityProviderConfig} instance
     */
    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    /**
     * Returns the unique identifier for the WeChat Identity Provider.
     * This ID is used internally within Keycloak to reference the provider.
     *
     * @return the unique ID of the provider, "wechat"
     */
    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Returns the configuration properties for the WeChat Identity Provider.
     * This method defines all the configuration fields required to set up the
     * WeChat integration, including app IDs, secrets, and additional options
     * like enabling the Open Platform or using Mini Programs.
     *
     * @return a list of {@link ProviderConfigProperty} defining the configurable fields
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()

                .property().name(WeChatIdentityProvider.OPEN_CLIENT_ENABLED)
                .label("Enable")
                .helpText("Enable?")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .add()

                .build();
    }
}
