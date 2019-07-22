package io.warp10.auth.openstack;

import java.util.Date;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import org.openstack4j.api.OSClient.OSClientV3;
import org.openstack4j.openstack.OSFactory;
import org.openstack4j.model.identity.v3.Token;
import org.openstack4j.model.identity.v3.Project;
import org.openstack4j.model.identity.v3.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.warp10.continuum.AuthenticationPlugin;
import io.warp10.quasar.token.thrift.data.ReadToken;
import io.warp10.quasar.token.thrift.data.WriteToken;
import io.warp10.script.WarpScriptException;
import io.warp10.warp.sdk.AbstractWarp10Plugin;

public class OpenstackAuthPlugin extends AbstractWarp10Plugin implements AuthenticationPlugin {

    private static final Logger log = LoggerFactory.getLogger(OpenstackAuthPlugin.class);

    private static final String KEYSTONE_URL = "openstack.keystone.url";
    private static final String USER_NAME = "openstack.keystone.user.name";
    private static final String USER_PASSWORD = "openstack.keystone.user.password";
    private static final String KEYSTONE_DOMAIN = "openstack.keystone.domain";
    private static final String APP_PREFIX = "openstack.app.prefix";

    private OSClientV3 openstackClient;
    private String appPrefix;

    private static final LoadingCache<String, ReadToken> readTokenCache = CacheBuilder.newBuilder()
        .maximumSize(10000)
        .expireAfterWrite(1, TimeUnit.MINUTES)
        .build(
            new CacheLoader<String, ReadToken>() {
                public ReadToken load(String key) throws Exception {
                    return new ReadToken();
                }
            }
        );

    private static final LoadingCache<String, WriteToken> writeTokenCache = CacheBuilder.newBuilder()
        .maximumSize(10000)
        .expireAfterWrite(1, TimeUnit.MINUTES)
        .build(
            new CacheLoader<String, WriteToken>() {
                public WriteToken load(String key) throws Exception {
                    return new WriteToken();
                }
            }
        );

    private static final LoadingCache<String, WarpScriptException> tokenBlackList = CacheBuilder.newBuilder()
        .maximumSize(10000)
        .expireAfterWrite(1, TimeUnit.MINUTES)
        .build(
            new CacheLoader<String, WarpScriptException>() {
                public WarpScriptException load(String token) throws Exception {
                    return new WarpScriptException();
                }
            }
        );

    public OpenstackAuthPlugin() {}

    @Override
    public void init(Properties p) {
        this.validateConfig(p);

        String url = p.getProperty(KEYSTONE_URL);
        String user = p.getProperty(USER_NAME);
        String pass = p.getProperty(USER_PASSWORD);

        this.appPrefix = p.getProperty(APP_PREFIX, "os.");
        this.openstackClient = OSFactory.builderV3()
            .endpoint(url)
            .credentials(user, pass)
            .authenticate();
    }

    @Override
    public ReadToken extractReadToken(String token) throws WarpScriptException {
        WarpScriptException we;
        ReadToken rtoken;

        // Check is token is blacklisted
        we = OpenstackAuthPlugin.tokenBlackList.getIfPresent(token);
        if (we != null) {
            throw we;
        }

        rtoken = OpenstackAuthPlugin.readTokenCache.getIfPresent(token);
        if (rtoken != null) {
            return rtoken;
        }
        rtoken = new ReadToken();

        Token osToken = this.openstackClient.identity().tokens().get(token);
        if (osToken == null) {
            return null;
        }

        we = this.checkExpiration(osToken);
        if (we != null) {
            OpenstackAuthPlugin.tokenBlackList.put(token, we);
            throw we;
        }

        Project osProject = token.getProject();
        User osUser = token.getUser();

        rtoken.setAppName(this.withPrefix(osProject.getName()));


        // TODO: manage roles

        return rtoken;
    }

    @Override
    public WriteToken extractWriteToken(String token) throws WarpScriptException {
        WarpScriptException we;

        // Check is token is blacklisted
        we = OpenstackAuthPlugin.tokenBlackList.getIfPresent(token);
        if (we != null) {
            throw we;
        }

        WriteToken wtoken;

        // Check if it's a known token
        wtoken = OpenstackAuthPlugin.writeTokenCache.getIfPresent(token);
        if (wtoken != null) {
            return wtoken;
        }
        wtoken = new WriteToken();

        Token osToken = this.openstackClient.identity().tokens().get(token);
        if (osToken == null) {
            return null;
        }

        we = this.checkExpiration(osToken);
        if (we != null) {
            OpenstackAuthPlugin.tokenBlackList.put(token, we);
            throw we;
        }

        Project osProject = token.getProject();
        User osUser = token.getUser();

        wtoken.setAppName(this.withPrefix(osProject.getName()));
        wtoken.setProducerId(osUser.getName().getBytes());

        // TODO: manage roles

        return wtoken;
    }

    /**
     * Ensure needed configuration keys are presents
     * @param p Warp10 configuration for this plugin
     */
    private void validateConfig(Properties p) {
        String[] keys = {KEYSTONE_URL, USER_NAME, USER_PASSWORD, KEYSTONE_DOMAIN};

        for (String key : keys) {
            if (!p.containsKey(key)) {
                log.error("Missing '" + key + "' in configuration");
            }
        }
    }

    /**
     * Add static Openstack prefix to an app name
     * @param app The app to prefix
     * @return New app name
     */
    private String withPrefix(String app) {
        if (app.startsWith(this.appPrefix)) {
            return app;
        }
        return this.appPrefix + app.trim();
    }

    /**
     * Validate an Openstack token issuance and expiration
     * @param token token to validate
     * @return exception or null
     */
    private static WarpScriptException checkExpiration(Token token) {
        Date now = new Date();
        Date de = token.getExpires();
        Date di = token.getIssuedAt();

        if (de.after(now)) {
            return new WarpScriptException("this token has been expired at: " + de.toString());
        }

        if (di.before(new Date())) {
            return new WarpScriptException("this token is not valid yet: " + di.toString());
        }

        return null;
    }
}