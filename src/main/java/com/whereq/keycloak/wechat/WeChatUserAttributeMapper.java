package com.whereq.keycloak.wechat;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.mappers.UserAttributeMapper;

/**
 * WeChatUserAttributeMapper is a user attribute mapper for integrating user attributes from WeChat into Keycloak.
 *
 * This mapper is intended to work with the "Claims" attribute in the "Mappers" tab of the WeChat identity provider configuration.
 * While this example demonstrates a different type of mapper, it provides a basic structure for handling WeChat user attributes.
 *
 * This mapper is primarily a placeholder or example to illustrate how to extend the functionality of user attribute mappers
 * to accommodate specific requirements for handling WeChat attributes.
 *
 * <p>
 * Example usage:
 * <pre>
 *     WeChatUserAttributeMapper mapper = new WeChatUserAttributeMapper();
 *     String[] compatibleProviders = mapper.getCompatibleProviders(); // Returns the compatible providers for this mapper.
 *     String mapperId = mapper.getId(); // Returns the unique ID of this mapper.
 * </pre>
 * </p>
 *
 * @author Tony Zhang
 * @since 2024-09-12
 */
public class WeChatUserAttributeMapper extends UserAttributeMapper {

	protected static final Logger logger = Logger.getLogger(WeChatUserAttributeMapper.class);

	private static final String[] COMPATIBLE_PROVIDERS = new String[] { WeChatIdentityProviderFactory.PROVIDER_ID };

	/**
	 * Returns the list of compatible providers for this user attribute mapper.
	 * This mapper is compatible with the WeChat identity provider.
	 *
	 * @return an array of compatible provider IDs, in this case, the WeChat provider ID.
	 */
	@Override
	public String[] getCompatibleProviders() {
		logger.debug("Returning compatible providers: " + String.join(", ", COMPATIBLE_PROVIDERS));
		return COMPATIBLE_PROVIDERS;
	}

	/**
	 * Returns the unique identifier for this user attribute mapper.
	 *
	 * @return the unique ID of this mapper.
	 */
	@Override
	public String getId() {
		String mapperId = "wechat-user-attribute-mapper";
		logger.debug("Returning mapper ID: " + mapperId);
		return mapperId;
	}

}
