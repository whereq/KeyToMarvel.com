package com.whereq.keycloak.wechat.utils;

import lombok.SneakyThrows;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * WeChatOfficialAccountUtil
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class WeChatOfficialAccountUtil {
    /**
     * The URL Echostr algorithm is a verification process used by WeChat to verify that the requests being
     * received by a server are actually from WeChat. This is typically used during the configuration of a
     * WeChat public account or when setting up a webhook. It involves hashing certain parameters using SHA-1
     * and comparing the result with a signature provided by WeChat.
     *
     * <p>
     * Below are the steps of the URL Echostr algorithm:
     * </p>
     *
     * <ol>
     *   <li><b>Receive Parameters from WeChat:</b>
     *       WeChat sends the following query parameters in the URL:
     *       <ul>
     *           <li>signature: The signature used for verification (sent by WeChat).</li>
     *           <li>timestamp: A timestamp when the request was made.</li>
     *           <li>nonce: A random number used to ensure the request is unique.</li>
     *           <li>echostr: A random string sent by WeChat to verify the connection (only for the initial validation request).</li>
     *       </ul>
     *   </li>
     *
     *   <li><b>Sort Parameters:</b>
     *       Sort the received parameters (token, timestamp, and nonce) lexicographically.
     *       Example:
     *       <pre>
     *         var sortedArr = Arrays.stream(new String[]{token, timestamp, nonce}).sorted().toArray();
     *       </pre>
     *   </li>
     *
     *   <li><b>Concatenate the Sorted Parameters:</b>
     *       Concatenate the sorted parameters into a single string.
     *       Example:
     *       <pre>
     *         StringBuilder content = new StringBuilder();
     *         for (var item : sortedArr) {
     *             content.append(item);
     *         }
     *       </pre>
     *   </li>
     *
     *   <li><b>Hash the Concatenated String:</b>
     *       Hash the concatenated string using the SHA-1 algorithm.
     *       Example:
     *       <pre>
     *         var hash = MessageDigest.getInstance("SHA-1");
     *         hash.update(content.toString().getBytes());
     *         var hashed = hash.digest();
     *       </pre>
     *   </li>
     *
     *   <li><b>Convert the Hash to Hexadecimal:</b>
     *       Convert the resulting hash (byte array) to a hexadecimal string.
     *       Example:
     *       <pre>
     *         var hexDigest = new StringBuilder();
     *         for (byte hashByte : hashed) {
     *             hexDigest.append(String.format("%02x", hashByte));
     *         }
     *       </pre>
     *   </li>
     *
     *   <li><b>Compare with WeChat's Signature:</b>
     *       Convert the hash to uppercase and compare it with the 'signature' parameter sent by WeChat.
     *       If they match, the request is confirmed as coming from WeChat, and the server should return
     *       the 'echostr' parameter as a response.
     *       Example:
     *       <pre>
     *         var upperCase = hexDigest.toString().toUpperCase();
     *         return upperCase.equals(signature.toUpperCase());
     *       </pre>
     *   </li>
     *
     *   <li><b>Return 'echostr':</b>
     *       If the signature matches, the server should return the 'echostr' parameter to confirm verification.
     *   </li>
     * </ol>
     *
     * <p><b>Usage Example (WeChat Official Documentation):</b></p>
     * Here’s an example of what the URL verification request might look like:
     * <pre>
     * http://yourdomain.com/wechat?signature=5d19752cd8577&timestamp=1372723149&nonce=153967457&echostr=8600142558596921017
     * </pre>
     *
     * If the request is valid, your server will return `echostr`, which in this case would be `8600142558596921017`.
     *
     * <p>This verification process is only done once during the initial setup of a WeChat public account to
     * ensure the legitimacy of the server that will receive messages or webhooks.</p>
     *
     * <p><b>References:</b></p>
     * <ul>
     *   <li><a href="https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/Access_Overview.html">WeChat Documentation</a></li>
     * </ul>
     */

    /**
     * Implementation of URL Echostr algorithm:
     * <p>
     * 1. Arrange the
     *      Token : the value configured by the user in the WeChat backend
     *      timestamp : the timestamp value passed when WeChat requests the URL
     *      nonce : the nonce value passed when WeChat requests the URL
     *    in alphabetical order;
     * 2. After arranging, concatenate them into a single string;
     * 3. If the result of converting this string using the sha1 algorithm is correct,
     *    it will match the value of echostr.
     */
    @SneakyThrows
    public static boolean isWeChatOfficialAccountMessage(String signature, String timestamp, String nonce) {
        var sortedArr = Arrays.stream(new String[]{"uni-heart", timestamp, nonce}).sorted().toArray();
        StringBuilder content = new StringBuilder();
        for (var item : sortedArr) {
            content.append(item);
        }

        var hash = MessageDigest.getInstance("SHA-1");
        hash.update(content.toString().getBytes());
        var hashed = hash.digest();
        var hexDigest = new StringBuilder();
        for (byte hashByte : hashed) {
            hexDigest.append(String.format("%02x", hashByte));
        }

        var upperCase = hexDigest.toString().toUpperCase();

        return upperCase.equals(signature.toUpperCase());
    }
}
