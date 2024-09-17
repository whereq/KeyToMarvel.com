package com.whereq.keycloak.wechat.resources;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.SneakyThrows;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import com.whereq.keycloak.wechat.utils.WeChatOfficialAccountUtil;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;

/**
 * WeChatCallbackResourceProvider handles the callbacks from WeChat Official Accounts. This provider
 * is necessary to properly handle WeChat's callback flow and integrate it with the Keycloak authentication process.
 *
 * The callback endpoint handles both GET and POST requests from WeChat for event verification and user scanning actions.
 *
 * Without this class, the Keycloak-WeChat authentication process would fail silently. Even though
 * it may appear in logs that Keycloak is receiving the callback, the endpoint will not function as expected without
 * this provider, which is why it is essential for proper handling of WeChat events within the realm-protected resource.
 *
 * This class implements the {@link RealmResourceProvider} interface, allowing it to be used as a resource in the
 * Keycloak realm context.
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatCallbackResourceProvider implements RealmResourceProvider {

    /** Logger instance for logging events and debugging information */
    protected static final Logger logger = Logger.getLogger(WeChatCallbackResourceProvider.class);

    /** The Keycloak session associated with this provider */
    private final KeycloakSession session;

    /**
     * Constructs a WeChatCallbackResourceProvider with the provided Keycloak session.
     *
     * @param session the Keycloak session
     */
    public WeChatCallbackResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Retrieves the current resource (this class). This method is part of the
     * {@link RealmResourceProvider} interface implementation.
     *
     * @return the current instance of WeChatCallbackResourceProvider
     */
    @Override
    public Object getResource() {
        return this;
    }

    /**
     * Closes any resources associated with this provider. In this case, no specific resources
     * are being closed.
     */
    @Override
    public void close() {
        // No-op: No resources to close in this implementation.
    }

    /**
     * Handles WeChat's GET callback request to verify the server by responding with the 'echostr' parameter
     * after validating the message signature.
     *
     * @param signature the signature sent by WeChat to verify the message
     * @param timestamp the timestamp of the request
     * @param nonce     a random nonce string
     * @param echostr   the string that WeChat expects to be returned if the message is verified
     * @return an OK response containing the echostr if verified, otherwise a NOT_ACCEPTABLE response
     */
    @GET
    @Path("wechat-callback")
    @Produces(MediaType.TEXT_PLAIN)
    public Response wechatCallback(@QueryParam("signature") String signature,
                                   @QueryParam("timestamp") String timestamp,
                                   @QueryParam("nonce") String nonce,
                                   @QueryParam("echostr") String echostr) {
        logger.info(String.format("Received WeChat callback request with signature: %s, timestamp: %s, nonce: %s, echostr: %s",
                signature, timestamp, nonce, echostr));

        if (WeChatOfficialAccountUtil.isWeChatOfficialAccountMessage(signature, timestamp, nonce)) {
            logger.info(String.format("WeChat callback verification successful with echostr: %s", echostr));
            return Response.ok(echostr).build();
        }

        logger.warn("WeChat callback verification failed.");
        return Response.notAcceptable(new ArrayList<>()).build();
    }

    /**
     * Handles WeChat's POST callback request, which contains an XML payload with event details.
     * This method processes events such as SCAN, and returns a JSON response indicating the action taken.
     *
     * Only events of type "SCAN" are processed. Other events are ignored with an appropriate message.
     *
     * @param xmlData the XML data sent by WeChat
     * @return a JSON response indicating whether the scan event was received or ignored
     */
    @SneakyThrows
    @POST
    @Path("wechat-callback")
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_JSON)
    public Response wechatCallback(String xmlData) {
        logger.info("Received WeChat server callback message.");

        // Parse the XML data
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xmlData)));
        var root = document.getDocumentElement();
        var xmlEvent = root.getElementsByTagName("Event").item(0).getTextContent();

        // Process only "SCAN" events
        if (!Objects.equals(xmlEvent, "SCAN")) {
            logger.info(String.format("Ignoring non-SCAN event: received event '%s'", xmlEvent));
            return Response.ok(Map.of("status", "not_scanned")).build();
        }

        var xmlTicket = root.getElementsByTagName("Ticket").item(0).getTextContent();
        var xmlFromUserName = root.getElementsByTagName("FromUserName").item(0).getTextContent();

        logger.debug(String.format("Processing SCAN event with Ticket: %s and FromUserName: %s", xmlTicket, xmlFromUserName));
        return Response.ok(Map.of("status", "scanned")).build();
    }
}
