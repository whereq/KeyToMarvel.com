package com.whereq.keycloak.wechat.resources;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * WeChatCallbackResourceProviderFactory is a factory class responsible for creating instances of
 * {@link WeChatCallbackResourceProvider}, which handles WeChat callback requests in Keycloak.
 *
 * This class is declared in the META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory,
 * following Keycloak's service provider mechanism.
 *
 * Although it's not strictly necessary to declare this factory in the services directory, having it improves modularity
 * and helps Keycloak discover and load the provider, ensuring smooth integration of WeChat callbacks into the Keycloak authentication flow.
 *
 * Keycloak uses this factory to create and initialize the {@link WeChatCallbackResourceProvider} during runtime,
 * allowing it to manage WeChat authentication processes tied to specific realms.
 *
 * @see WeChatCallbackResourceProvider
 * @see org.keycloak.services.resource.RealmResourceProviderFactory
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatCallbackResourceProviderFactory implements RealmResourceProviderFactory {

    /**
     * Creates a new instance of {@link WeChatCallbackResourceProvider} when invoked by Keycloak.
     *
     * @param session the current {@link KeycloakSession} context
     * @return a new {@link WeChatCallbackResourceProvider} instance
     */
    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new WeChatCallbackResourceProvider(session);
    }

    /**
     * Initializes the factory. This method allows for configuration using Keycloak's configuration system.
     * Currently, no specific configuration is needed for the WeChat callback provider.
     *
     * @param config the configuration scope that can be used to retrieve specific settings
     */
    @Override
    public void init(Config.Scope config) {
        // No specific initialization needed for WeChat callback resource provider at this stage
    }

    /**
     * Performs post-initialization steps for the factory. This method can be used to perform any setup that
     * depends on other providers or resources that are initialized after this factory.
     *
     * @param factory the {@link KeycloakSessionFactory} used to interact with other Keycloak services
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed for this factory
    }

    /**
     * Closes the factory and performs any cleanup operations, if necessary.
     * Currently, there are no resources or processes that need to be closed for this provider.
     */
    @Override
    public void close() {
        // No resources to close
    }

    /**
     * Returns the unique identifier for this provider factory, which is used by Keycloak to reference this provider.
     *
     * @return the ID of the provider factory
     */
    @Override
    public String getId() {
        return "WeChatCallbackResourceProviderFactory";
    }
}
