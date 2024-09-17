package com.whereq.keycloak.wechat.utils;

import com.whereq.keycloak.wechat.WeChatIdentityProvider;

/**
 * UserAgentUtil
 *
 * @author Tony Zhang (Tony at whereq dot com)
 * @since 2024-09-12
 */
public class UserAgentUtil {

    /**
     * Check if the user agent is from WeChat browser.
     *
     * @param userAgent
     * @return
     */
    public static boolean isWeChatBrowser(String userAgent) {
        return userAgent.indexOf(WeChatIdentityProvider.WECHATFLAG) > 0;
    }
}
