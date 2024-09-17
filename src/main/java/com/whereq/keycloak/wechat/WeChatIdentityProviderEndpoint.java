package com.whereq.keycloak.wechat;

import com.whereq.keycloak.wechat.utils.UserAgentUtil;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import java.util.Objects;

/**
 * WeChatIdentityProviderEndpoint
 * This class handles the WeChat Identity Provider integration within the Keycloak authentication flow.
 * It processes authentication requests from WeChat and passes the authentication result back to Keycloak.
 * The reason is that the WeChat authentication process requires a callback endpoint to verify the signature,
 *
 * The WeChatIdentityProviderEndpoint class implements the OAuth2 authorization code flow and handles
 * user-agent-based decisions such as WeChat browser detection.
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatIdentityProviderEndpoint {
    protected static final Logger logger = Logger.getLogger(WeChatIdentityProviderEndpoint.class);

    private final WeChatIdentityProvider weChatIdentityProvider;
    private final IdentityProvider.AuthenticationCallback callback;
    private final RealmModel realmModel;
    private final EventBuilder event;

    @Context
    protected ClientConnection clientConnection;

    @Context
    protected org.keycloak.http.HttpRequest request;

    private KeycloakSession keycloakSession;

    /**
     * Constructor for WeChatIdentityProviderEndpoint.
     *
     * @param weChatIdentityProvider The WeChat identity provider instance.
     * @param callback Callback function for handling authentication results.
     * @param realmModel The realm model in Keycloak.
     * @param event EventBuilder for logging authentication events.
     * @param session The KeycloakSession object to manage the session.
     */
    public WeChatIdentityProviderEndpoint(
            WeChatIdentityProvider weChatIdentityProvider,
            IdentityProvider.AuthenticationCallback callback,
            RealmModel realmModel,
            EventBuilder event,
            KeycloakSession session) {
        this.weChatIdentityProvider = weChatIdentityProvider;
        this.realmModel = realmModel;
        this.callback = callback;
        this.event = event;
        this.keycloakSession = session;
    }

    /**
     * Processes the WeChat OAuth2 authentication response.
     *
     * @param state The OAuth2 state parameter.
     * @param authorizationCode The OAuth2 authorization code.
     * @param error Any error returned from WeChat.
     * @param openid The openid from WeChat (optional).
     * @param clientId The client ID for the identity provider.
     * @param tabId The tab ID associated with the authentication session.
     * @return A JAX-RS Response object representing the outcome of the authentication process.
     */
    @GET
    public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                 @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                 @QueryParam(OAuth2Constants.ERROR) String error,
                                 @QueryParam(OAuth2Constants.SCOPE_OPENID) String openid,
                                 @QueryParam("clientId") String clientId,
                                 @QueryParam("tabId") String tabId) {

        logger.info(String.format("OAUTH2_PARAMETER_CODE = %s, %s, %s, %s, %s", authorizationCode, error, openid, clientId, tabId));

        if (state == null) {
            return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
        }

        var wechatLoginType = WeChatLoginType.FROM_PC_QR_CODE_SCANNING;

        String userAgent =
                weChatIdentityProvider
                        .getKeycloakSession()
                        .getContext()
                        .getRequestHeaders()
                        .getHeaderString("user-agent").toLowerCase();

        if (UserAgentUtil.isWeChatBrowser(userAgent)) {
            logger.info("user-agent=wechat");
            wechatLoginType = WeChatLoginType.FROM_WECHAT_BROWSER;
        }

        if (error != null) {
            logger.warn(error + " for broker login " + weChatIdentityProvider.getConfig().getProviderId());
            if (error.equals(WeChatIdentityProvider.ACCESS_DENIED)) {
                logger.error(WeChatIdentityProvider.ACCESS_DENIED + " for broker login " + weChatIdentityProvider.getConfig().getProviderId() + " " + state);
                sendErrorEvent();
                return callback.cancelled(this.weChatIdentityProvider.getConfig());
            } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED) || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                return callback.error(error);
            } else {
                return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }

        AuthenticationSessionModel authenticationSessionModel = this.callback.getAndVerifyAuthenticationSession(state);
        keycloakSession.getContext().setAuthenticationSession(authenticationSessionModel);

        try {
            if (authorizationCode != null) {
                BrokeredIdentityContext federatedIdentity =
                        weChatIdentityProvider.sendTokenRequest(authorizationCode,
                                wechatLoginType);
                federatedIdentity.setAuthenticationSession(authenticationSessionModel);
                return this.callback.authenticated(federatedIdentity);
            }
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            logger.error("Failed to make identity provider (weixin) oauth callback", e);
        }
        return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    /**
     * Handles error cases for identity provider logins.
     *
     * @param message The error message to be displayed.
     * @return A JAX-RS Response object representing the error page.
     */
    private Response errorIdentityProviderLogin(String message) {
        return errorIdentityProviderLogin(message, Response.Status.BAD_GATEWAY);
    }


    /**
     * Handles error cases for identity provider logins with a specific HTTP status.
     *
     * @param message The error message to be displayed.
     * @param status The HTTP status to return in the response.
     * @return A JAX-RS Response object representing the error page with the provided status.
     */
    private Response errorIdentityProviderLogin(String message, Response.Status status) {
        sendErrorEvent();
        return ErrorPage.error(keycloakSession, null, status, message);
    }


    /**
     * Sends an error event for failed identity provider login attempts.
     */
    private void sendErrorEvent() {
        event.event(EventType.IDENTITY_PROVIDER_LOGIN);
        event.detail("idp", weChatIdentityProvider.getConfig().getProviderId());
        event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
    }

}