package com.whereq.keycloak.wechat;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import java.util.UUID;

import jakarta.ws.rs.core.*;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.whereq.keycloak.wechat.utils.UserAgentUtil;

/**
 * WeChatIdentityProvider class provides the implementation for handling WeChat OAuth2 identity provider
 * in Keycloak, supporting both login via WeChat browser and WeChat Mini Program.
 * It extends the {@link AbstractOAuth2IdentityProvider} for OAuth2 authentication
 * and implements the {@link SocialIdentityProvider} interface for social login flows.
 *
 * The class defines endpoints for redirecting users to WeChat for authentication,
 * retrieving access tokens, and mapping user profiles to Keycloak identity contexts.
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    private static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
    public static final String OPEN_AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";
    public static final String OPEN_DEFAULT_SCOPE = "snsapi_login";
    public static final String APP_ID = "appid";
    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";
    public static final String CLIENT_ID = "clientId";
    public static final String OPEN_CLIENT_ENABLED = "openClientEnabled";
    public static final String WECHAT_MOBILE_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    public static final String WECHAT_MP_DEFAULT_SCOPE = "snsapi_userinfo";
    public static final String CUSTOMIZED_LOGIN_URL_FOR_PC = "customizedLoginUrl";
    public static final String WECHAT_MP_APP_ID = "clientId2";
    public static final String WECHAT_MP_APP_SECRET = "clientSecret2";
    public static final String PROFILE_URL = "https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN";
    public static final String OPENID = "openid";
    public static final String OAUTH2_GRANT_TYPE_CLIENT_CREDENTIAL = "client_credential";
    public static final String WECHATFLAG = "micromessenger";

    /**
     * Constructor for WeChatIdentityProvider.
     *
     * @param keycloakSession Keycloak keycloakSession context
     * @param oAuth2IdentityProviderConfig OAuth2IdentityProviderConfig configuration specific to WeChat provider
     */
    public WeChatIdentityProvider(
            KeycloakSession keycloakSession,
            OAuth2IdentityProviderConfig oAuth2IdentityProviderConfig
    ) {
        super(keycloakSession, oAuth2IdentityProviderConfig);
        oAuth2IdentityProviderConfig.setAuthorizationUrl(OPEN_AUTH_URL);
        oAuth2IdentityProviderConfig.setTokenUrl(TOKEN_URL);
    }

    /**
     * Constructor for WeChatIdentityProvider with a custom weChatIdentityProviderConfig.
     *
     * @param keycloakSession Keycloak keycloakSession context
     * @param weChatIdentityProviderConfig WeChatIdentityProviderConfig configuration specific to WeChat provider
     */
    public WeChatIdentityProvider(
            KeycloakSession keycloakSession,
            WeChatIdentityProviderConfig weChatIdentityProviderConfig
    ) {
        super(keycloakSession, weChatIdentityProviderConfig);
        weChatIdentityProviderConfig.setAuthorizationUrl(OPEN_AUTH_URL);
        weChatIdentityProviderConfig.setTokenUrl(TOKEN_URL);
        weChatIdentityProviderConfig.setUserInfoUrl(PROFILE_URL);
    }

    /**
     * Handles the authenticationCallback after authentication from WeChat.
     *
     * @param realmModel the realmModel the user is authenticating in
     * @param authenticationCallback the authentication authenticationCallback object
     * @param eventBuilder the eventBuilder builder used for logging Keycloak events
     * @return an instance of WeChatIdentityProviderEndpoint
     */
    @Override
    public Object callback(
            RealmModel realmModel,
            AuthenticationCallback authenticationCallback,
            EventBuilder eventBuilder
    ) {
        logger.info(String.format("Received authenticationCallback for eventBuilder = %s", eventBuilder));
        return new WeChatIdentityProviderEndpoint(this, authenticationCallback, realmModel, eventBuilder, session);
    }

    /**
     * Defines whether the provider supports external exchange, which is true for WeChat.
     *
     * @return true if external exchange is supported
     */
    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    /**
     * Extracts identity information from the user's WeChat profile.
     *
     * @param eventBuilder the eventBuilder builder used for logging Keycloak events
     * @param profile the JSON profile received from WeChat
     * @return BrokeredIdentityContext containing the extracted user information
     */
    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(
            EventBuilder eventBuilder,
            JsonNode profile
    ) {
        String unionId = getJsonProperty(profile, "unionid");
        var openId = getJsonProperty(profile, "openid");
        var externalUserId = (unionId != null && !unionId.isEmpty()) ? unionId : openId;

        BrokeredIdentityContext user = new BrokeredIdentityContext(externalUserId, getConfig());
        user.setUsername(externalUserId);
        user.setBrokerUserId(externalUserId);
        user.setModelUsername(externalUserId);
        user.setFirstName(getJsonProperty(profile, "nickname"));
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    /**
     * Processes the federated identity by retrieving the user's information from WeChat.
     *
     * @param response the OAuth2 response
     * @param wechatLoginType the login type (e.g., WeChat Mini Program or browser)
     * @return BrokeredIdentityContext containing user identity and token information
     */
    public BrokeredIdentityContext getFederatedIdentity(
            String response,
            WeChatLoginType wechatLoginType) {
        var accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());

        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }

        BrokeredIdentityContext context = null;
        try {
            JsonNode profile;
            if (WeChatLoginType.FROM_WECHAT_BROWSER.equals(wechatLoginType)) {
                String openid = extractTokenFromResponse(response, OPENID);
                String url = PROFILE_URL.replace("ACCESS_TOKEN", accessToken).replace("OPENID", openid);
                profile = SimpleHttp.doGet(url, session).asJson();
            } else {
                profile = new ObjectMapper().readTree(response);
            }
            logger.info("Retrieved user info from WeChat: " + profile.toString());
            context = extractIdentityFromProfile(null, profile);
        } catch (IOException e) {
            logger.error("Error parsing user profile from WeChat response", e);
        }

        assert context != null;
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        return context;
    }

    /**
     * Initiates the WeChat login process by redirecting the user to the appropriate WeChat login URL.
     *
     * @param authenticationRequest the authentication authenticationRequest from Keycloak
     * @return a JAX-RS {@link Response} that redirects the user to WeChat
     */
    @Override
    public Response performLogin(
            AuthenticationRequest authenticationRequest
    ) {
        logger.info(String.format("Performing login for authenticationRequest URI = %s",
                authenticationRequest != null && authenticationRequest.getUriInfo() != null ? authenticationRequest.getUriInfo().getAbsolutePath().toString() : "null"));

        try {
            URI authorizationUrl = createAuthorizationUrl(Objects.requireNonNull(authenticationRequest)).build();
            logger.info(String.format("Generated authorization URL = %s", authorizationUrl.toString()));

            String userAgent = authenticationRequest.getSession().getContext().getRequestHeaders().getHeaderString("user-agent").toLowerCase();
            logger.info(String.format("User-Agent: %s", userAgent));

            if (UserAgentUtil.isWeChatBrowser(userAgent)) {
                URI location = URI.create(String.format("%s#wechat_redirect", authorizationUrl));
                logger.info(String.format("Redirecting user to WeChat URL = %s", location));
                return Response.seeOther(location).build();
            } else {
                return Response.seeOther(authorizationUrl).build();
            }
        } catch (Exception e) {
            logger.error("Failed to create authorization URL for WeChat login", e);
            throw new IdentityBrokerException("Could not create WeChat login authorization URL", e);
        }
    }

    @Override
    /**
     * Creates the authorization URL for initiating the OAuth2 authentication process with WeChat.
     * The URL generation differs based on the type of client (WeChat browser, Open client, or custom client).
     * It handles various query parameters like scope, state, response type, redirect URI, and others.
     *
     * @param authenticationRequest The authentication request containing necessary session and context information.
     * @return A {@link UriBuilder} object with the constructed authorization URL.
     */
    protected UriBuilder createAuthorizationUrl(
            AuthenticationRequest authenticationRequest
    ) {
        UriBuilder uriBuilder = null;

        // Retrieve user agent from the request headers
        String userAgent = authenticationRequest.getSession().getContext().getRequestHeaders().getHeaderString("user-agent").toLowerCase();
        logger.info(String.format("Creating authorization URL, detected User-Agent: %s", userAgent));

        // Get configuration settings
        var config = getConfig();
        var configMap = config.getConfig();
        var clientId = configMap.get(CLIENT_ID);

        // Case 1: WeChat browser detected
        if (UserAgentUtil.isWeChatBrowser(userAgent)) {
            logger.info("WeChat browser detected, building URL for mobile WeChat login.");

            uriBuilder = UriBuilder.fromUri(WECHAT_MOBILE_AUTH_URL);
            uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, WECHAT_MP_DEFAULT_SCOPE)
                    .queryParam(OAUTH2_PARAMETER_STATE, authenticationRequest.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                    .queryParam(APP_ID, getConfig().getClientId())
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, authenticationRequest.getRedirectUri());

            return uriBuilder;
        }

        // Case 2: Open client enabled
        if (config instanceof WeChatIdentityProviderConfig) {
            if (clientId != null) {
                logger.info("Open client enabled, building URL for Open WeChat login.");

                uriBuilder = UriBuilder.fromUri(OPEN_AUTH_URL);
                uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, OPEN_DEFAULT_SCOPE)
                        .queryParam(OAUTH2_PARAMETER_STATE, authenticationRequest.getState().getEncoded())
                        .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                        .queryParam(APP_ID, clientId)
                        .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, authenticationRequest.getRedirectUri());

                return uriBuilder;
            }

            // Case 3: Customized login URL for PC
            var customizedLoginUrlForPc = ((WeChatIdentityProviderConfig) config).getCustomizedLoginUrlForPc();
            if (customizedLoginUrlForPc != null && !customizedLoginUrlForPc.isEmpty()) {
                logger.info("Using customized login URL for PC.");

                uriBuilder = UriBuilder.fromUri(customizedLoginUrlForPc);
                uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, WECHAT_MP_DEFAULT_SCOPE)
                        .queryParam(OAUTH2_PARAMETER_STATE, authenticationRequest.getState().getEncoded())
                        .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                        .queryParam(APP_ID, config.getConfig().get(WECHAT_MP_APP_ID))
                        .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, authenticationRequest.getRedirectUri());

                return uriBuilder;
            }
        }

        // Case 4: Fallback to default authorization URL
        logger.info("Falling back to default authorization URL configuration.");
        uriBuilder = UriBuilder.fromUri(config.getAuthorizationUrl());
        uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, config.getDefaultScope())
                .queryParam(OAUTH2_PARAMETER_STATE, authenticationRequest.getState().getEncoded())
                .queryParam(APP_ID, config.getClientId())
                .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, authenticationRequest.getRedirectUri());

        // Adding login hint if available
        String loginHint = authenticationRequest.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (getConfig().isLoginHint() && loginHint != null) {
            logger.info("Adding login hint to the authorization URL.");
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        // Adding prompt if specified in the request or config
        String prompt = getConfig().getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = authenticationRequest.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            logger.info(String.format("Adding prompt to the authorization URL: %s", prompt));
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        // Adding nonce for replay protection
        String nonce = authenticationRequest.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = UUID.randomUUID().toString();
            authenticationRequest.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
            logger.info("Generated new nonce for authorization request.");
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        // Adding ACR values if available
        String acr = authenticationRequest.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            logger.info(String.format("Adding ACR values to the authorization URL: %s", acr));
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }

        logger.info("Authorization URL successfully created.");
        return uriBuilder;
    }


    public BrokeredIdentityContext sendTokenRequest(
            String authorizationCode,
            WeChatLoginType weChatLoginType
    ) throws IOException {
        SimpleHttp.Response response = generateTokenRequest(authorizationCode, weChatLoginType).asResponse();

        if (response.getStatus() > 299) {
            logger.warn("Error response from apple: status=" + response.getStatus() + ", body=" + response.asString());
            return null;
        }

        BrokeredIdentityContext federatedIdentity = getFederatedIdentity(response.asString(), WeChatLoginType.FROM_WECHAT_BROWSER);
        federatedIdentity.setIdp(WeChatIdentityProvider.this);
        return federatedIdentity;
    }

    public SimpleHttp generateTokenRequest(String authorizationCode, WeChatLoginType wechatLoginType) {
        String ua = this.getKeycloakSession().getContext().getRequestHeaders().getHeaderString("user-agent").toLowerCase();
        if (UserAgentUtil.isWeChatBrowser(ua)) {
            logger.info("user-agent=wechat");
            wechatLoginType = WeChatLoginType.FROM_WECHAT_BROWSER;
        }
        logger.info(String.format("generateTokenRequest, code = %s, loginType = %s", authorizationCode, wechatLoginType));

        if (WeChatLoginType.FROM_WECHAT_BROWSER.equals(wechatLoginType)) {

            var mobileMpClientId = this.getConfig().getClientId();
            var mobileMpClientSecret = this.getConfig().getClientSecret();

            logger.info(String.format("from wechat browser, posting to %s for fetching token, with mobileMpClientId = %s, mobileMpClientSecret = %s",
                    this.getConfig().getTokenUrl(), mobileMpClientId, mobileMpClientSecret));

            return SimpleHttp.doGet(this.getConfig().getTokenUrl(), session)
                    .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(APP_ID, mobileMpClientId)
                    .param(OAUTH2_PARAMETER_CLIENT_SECRET, mobileMpClientSecret)
                    .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_CLIENT_CREDENTIAL);

        } else {
            return SimpleHttp.doPost(this.getConfig().getTokenUrl(), session)
                    .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(APP_ID, this.getConfig().getClientId())
                    .param(OAUTH2_PARAMETER_CLIENT_SECRET, this.getConfig().getClientSecret())
                    .param(OAUTH2_PARAMETER_REDIRECT_URI, this.getConfig().getConfig().get(OAUTH2_PARAMETER_REDIRECT_URI))
                    .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);
        }

    }

    @Override
    protected String getDefaultScopes() {
        return OPEN_DEFAULT_SCOPE;
    }

    public KeycloakSession getKeycloakSession() {
        return session;
    }
}
