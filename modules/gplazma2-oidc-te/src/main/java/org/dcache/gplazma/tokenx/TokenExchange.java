package org.dcache.gplazma.tokenx;

import static java.util.Objects.requireNonNull;
import static org.dcache.gplazma.util.Preconditions.checkAuthentication;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.util.EntityUtils;
import org.dcache.auth.BearerTokenCredential;
import org.dcache.auth.attributes.Restriction;
import org.dcache.gplazma.AuthenticationException;
import org.dcache.gplazma.plugins.GPlazmaAuthenticationPlugin;
import org.dcache.gplazma.util.JsonWebToken;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.VisibleForTesting;


public class TokenExchange implements GPlazmaAuthenticationPlugin {

    private final static Logger LOG = LoggerFactory.getLogger(TokenExchange.class);

    public final static String TOKEN_EXCHANGE_URL = "gplazma.oidc-te.url";
    public final static String CLIENT_ID = "gplazma.oidc-te.client-id";
    public final static String CLIENT_SECRET = "gplazma.oidc-te.client-secret";

    public final static String PRE_EXCHANGE_URL = "gplazma.oidc-te.pre-exchange-url";
    public final static String PRE_EXCHANGE_CLIENT_ID = "gplazma.oidc-te.pre-exchange-client-id";
    public final static String PRE_EXCHANGE_CLIENT_SECRET = "gplazma.oidc-te.pre-exchange-client-secret";
    public final static String PRE_EXCHANGE_AUDIENCE = "gplazma.oidc-te.pre-exchange-audience";

    private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final String PRE_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

    private final CloseableHttpClient client;

    private final String tokenExchangeURL;
    private final String clientID;
    private final String clientSecret;

    private final String preExchangeURL;
    private final String preExchangeClientID;
    private final String preExchangeClientSecret;
    private final String preExchangeAudience;

    public TokenExchange (Properties properties) {
        this(properties, HttpClients.createDefault());
    }

    @VisibleForTesting
    TokenExchange (Properties properties, CloseableHttpClient client) {
        tokenExchangeURL = properties.getProperty(TOKEN_EXCHANGE_URL);
        clientID = properties.getProperty(CLIENT_ID);
        clientSecret = properties.getProperty(CLIENT_SECRET);

        preExchangeURL = properties.getProperty(PRE_EXCHANGE_URL);
        preExchangeClientID = properties.getProperty(PRE_EXCHANGE_CLIENT_ID);
        preExchangeClientSecret = properties.getProperty(PRE_EXCHANGE_CLIENT_SECRET);
        preExchangeAudience = properties.getProperty(PRE_EXCHANGE_AUDIENCE);

        this.client = requireNonNull(client);
    }

    private boolean isPreExchangeEnabled() {
        return preExchangeURL != null && !preExchangeURL.isBlank();
    }

    @Override
    public void authenticate(Set<Object> publicCredentials, Set<Object> privateCredentials,
        Set<Principal> identifiedPrincipals, Set<Restriction> restrictions)
        throws AuthenticationException {

        BearerTokenCredential credential = null;
        for (Object c : privateCredentials) {
            if (c instanceof BearerTokenCredential) {

                checkAuthentication(credential == null, "Multiple bearer token credentials");
                credential = (BearerTokenCredential) c;

            }
        }

        if (credential == null) {
            throw new AuthenticationException("No bearer token credential found");
        }

        String token = credential.getToken();
        LOG.debug("Found bearer token: {}", token);

        checkAuthentication(token != null, "No bearer token in the credentials");


        try {
            String assertion = isPreExchangeEnabled() ? preExchange(token) : token;
            String exchangedToken = tokenExchange(assertion);
            privateCredentials.remove(credential);
            privateCredentials.add(new BearerTokenCredential(exchangedToken));

        } catch ( IOException | URISyntaxException e ) {
            throw new AuthenticationException("Unable to process token: " + e.getMessage());
        }

    }

    @VisibleForTesting
    String preExchange(String token) throws IOException, URISyntaxException {
        URI uri = new URIBuilder(preExchangeURL).build();
        HttpPost httpPost = new HttpPost(uri);
        httpPost.setEntity(new UrlEncodedFormEntity(List.of(
            new BasicNameValuePair("grant_type", PRE_EXCHANGE_GRANT_TYPE),
            new BasicNameValuePair("subject_token", token),
            new BasicNameValuePair("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            new BasicNameValuePair("requested_token_type", "urn:ietf:params:oauth:token-type:access_token"),
            new BasicNameValuePair("audience", preExchangeAudience),
            new BasicNameValuePair("scope", "openid")
        )));

        UsernamePasswordCredentials clientCreds =
            new UsernamePasswordCredentials(preExchangeClientID, preExchangeClientSecret);
        BasicScheme scheme = new BasicScheme(StandardCharsets.UTF_8);
        try {
            httpPost.addHeader(scheme.authenticate(clientCreds, httpPost, new BasicHttpContext()));
        } catch (org.apache.http.auth.AuthenticationException e) {
            throw new IOException("Unable to build pre-exchange request: " + e.getMessage(), e);
        }

        String result = postForAccessToken(httpPost);
        LOG.debug("Pre-exchanged Access Token: {}", result);
        return result;
    }

    @VisibleForTesting
    String tokenExchange(String token) throws IOException, URISyntaxException {
        URI uri = new URIBuilder(tokenExchangeURL).build();
        HttpPost httpPost = new HttpPost(uri);
        httpPost.setEntity(new UrlEncodedFormEntity(List.of(
            new BasicNameValuePair("client_id", clientID),
            new BasicNameValuePair("client_secret", clientSecret),
            new BasicNameValuePair("grant_type", GRANT_TYPE),
            new BasicNameValuePair("assertion", token)
        )));

        String result = postForAccessToken(httpPost);
        LOG.debug("Exchanged Access Token: {}", result);

        if (JsonWebToken.isCompatibleFormat(result)) {
            try {
                JsonWebToken jwt = new JsonWebToken(result);
                LOG.debug("Found issuer: {}", jwt.getPayloadString("iss"));

            } catch (IOException e) {
                LOG.debug("Failed to parse token: {}", e.toString());
            }
        }

        return result;
    }

    private String postForAccessToken(HttpPost httpPost) throws IOException {
        String responseBody;

        try (CloseableHttpResponse response = this.client.execute(httpPost)) {
            int status = response.getStatusLine().getStatusCode();
            HttpEntity responseEntity = response.getEntity();
            responseBody = EntityUtils.toString(responseEntity);
            if (status < 200 || status >= 300) {
                throw new IOException("Token endpoint returned HTTP " + status + ": " + responseBody);
            }
            LOG.debug("Response: {}", response);
            LOG.debug("Response body: {}", responseBody);
        }

        JSONObject result_json = new JSONObject(responseBody);

        if (!result_json.has("access_token")) {
            throw new IOException("response has no access_token");
        }

        return result_json.get("access_token").toString();
    }
}
