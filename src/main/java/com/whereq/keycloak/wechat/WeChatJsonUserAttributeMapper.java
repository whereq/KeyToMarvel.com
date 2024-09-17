package com.whereq.keycloak.wechat;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;

/**
 * WeChatJsonUserAttributeMapper is an implementation of {@link AbstractJsonUserAttributeMapper}
 * that facilitates mapping user attributes from WeChat's JSON responses to Keycloak user attributes.
 *
 * This mapper allows the "Social Profile JSON Field Path" attribute in the "Mappers" tab of the
 * WeChat identity provider configuration. It enables the mapping of JSON fields received from WeChat
 * to specific attributes within Keycloak, allowing for customized user profile integration.
 *
 * <p>
 * Example usage:
 * <pre>
 *     WeChatJsonUserAttributeMapper mapper = new WeChatJsonUserAttributeMapper();
 *     mapper.getCompatibleProviders(); // Returns the compatible providers for this mapper.
 * </pre>
 * </p>
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatJsonUserAttributeMapper extends AbstractJsonUserAttributeMapper {

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
		String mapperId = "wechat-json-user-attribute-mapper";
		logger.debug("Returning mapper ID: " + mapperId);
		return mapperId;
	}

}
