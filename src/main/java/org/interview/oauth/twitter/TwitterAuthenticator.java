/**
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * ________  __    __  ________    ____       ______   *
 * /_/_/_/_/ /_/   /_/ /_/_/_/_/  _/_/_/_   __/_/_/_/   *
 * /_/_____  /_/___/_/    /_/    /_/___/_/  /_/          *
 * /_/_/_/_/   /_/_/_/    /_/    /_/_/_/_/  /_/           *
 * ______/_/       /_/    /_/    /_/   /_/  /_/____        *
 * /_/_/_/_/       /_/    /_/    /_/   /_/    /_/_/_/ . io  *
 * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
package org.interview.oauth.twitter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Provide access to the Twitter API by implementing the required OAuth2 flow
 *
 * @author Sytac
 */
public class TwitterAuthenticator {

    private final String consumerKey;
    private final String consumerSecret;
    private String bearerToken;
    private static final String OAUTH2_TOKEN_URL = "https://api.twitter.com/oauth2/token";

    public TwitterAuthenticator(String consumerKey, String consumerSecret) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
    }

    /**
     * Get the bearer token
     *
     * @return The bearer token
     */
    public String getBearerToken() throws TwitterAuthenticationException {
        if (bearerToken == null) {
            bearerToken = requestAccessToken();
        }
        return bearerToken;
    }

    /**
     * Create a request to Twitter OAUTH2 api for getting the token
     *
     * @return The access token
     */
    private String requestAccessToken() throws TwitterAuthenticationException {
        String authorizationHeader = "Basic " + encodeCredentialsToBase64(consumerKey, consumerSecret);
        String[] headers = {"Authorization", authorizationHeader, "Content-Type", "application/x-www-form-urlencoded;charset=UTF-8"};
        String requestBody = "grant_type=client_credentials";

        HttpClient httpClient = HttpClient.newBuilder().build();

        URI uri = URI.create(OAUTH2_TOKEN_URL);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .headers(headers)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String token = getTokenFromBody(response.body());
            return token;
        } catch (Exception e) {
            throw new TwitterAuthenticationException("Unable to get the bearer token: " + e.getMessage(), e);
        }

    }

    /**
     * Return credentials in base64
     *
     * @param consumerKey The application consumer key
     * @param consumerSecret The application consumer secret
     * @return String with encoded credentials
     */
    private String encodeCredentialsToBase64(String consumerKey, String consumerSecret) {
        String credentials = consumerKey + ":" + consumerSecret;
        byte[] encodedCredentials = Base64.getEncoder().encode(credentials.getBytes(StandardCharsets.UTF_8));
        return new String(encodedCredentials, StandardCharsets.UTF_8);
    }

    /**
     * Return access_token taken from response
     *
     * @param responseBody The OAUTH2 token response body
     * @return String with the access_token
     */
    private String getTokenFromBody(String responseBody) throws TwitterAuthenticationException {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(responseBody);
            return rootNode.get("access_token").asText();
        } catch (Exception e) {
            throw new TwitterAuthenticationException("Unable to retrieve the access_token from response: " + e.getMessage(), e);
        }

    }
}
