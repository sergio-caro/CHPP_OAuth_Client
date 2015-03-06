/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package chpp_oauth_client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import oauth.signpost.OAuth;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.OAuthProvider;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.basic.DefaultOAuthProvider;
import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import oauth.signpost.exception.OAuthNotAuthorizedException;

/**
 *
 * @author sergio
 * @version 1.0
 * @see OAuth manual & Constants
 */
public class CHPP_OAuth_Client {

    private OAuthConsumer consumer;

    /**
     * Object constructor
     *
     * @see Constants for constants description
     */
    public CHPP_OAuth_Client() {
        OAuthConsumer consumer = new DefaultOAuthConsumer(Constants.CONSUMER_KEY, Constants.CONSUMER_SECRET);
    }

    /**
     * Object contructor
     *
     * @deprecated Preferably use constructor without params
     * @param consumer_key
     * @param consumer_secret
     */
    public CHPP_OAuth_Client(String consumer_key, String consumer_secret) {
        OAuthConsumer consumer = new DefaultOAuthConsumer(consumer_key, consumer_secret);
    }

    /**
     * This method generates an aunthentication method with Hattrick to retrieve
     * OAuth tokens
     *
     * @return an OAutConsumer object with the Token and Secret token of the
     * client
     */
    public OAuthConsumer create_new_user() {
        try {
            OAuthProvider provider = new DefaultOAuthProvider(
                    Constants.REQUEST_TOKEN_URL,
                    Constants.ACCESS_TOKEN_URL,
                    Constants.AUTHORIZE_URL);

            System.out.println("Fetching request token from Hattrick...");

            String authUrl = provider.retrieveRequestToken(consumer, OAuth.OUT_OF_BAND);
            System.out.println("Request token: " + consumer.getToken());
            System.out.println("Token secret: " + consumer.getTokenSecret());

            System.out.println("Now visit:\n" + authUrl + "\n... and grant this app authorization");
            System.out.println("Enter the PIN code and hit ENTER when you're done:");

            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String pin = br.readLine();
            System.out.println("Fetching access token from Hattricks...");

            provider.retrieveAccessToken(consumer, pin);

            System.out.println("Access token: " + consumer.getToken());
            System.out.println("Token secret: " + consumer.getTokenSecret());
            OAuthConsumer ret = new DefaultOAuthConsumer("", "");
            ret.setTokenWithSecret(consumer.getToken(), consumer.getTokenSecret());
            return ret;
        } catch (OAuthMessageSignerException ex) {
            Logger.getLogger(CHPP_OAuth_Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OAuthNotAuthorizedException ex) {
            Logger.getLogger(CHPP_OAuth_Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OAuthExpectationFailedException ex) {
            Logger.getLogger(CHPP_OAuth_Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OAuthCommunicationException ex) {
            Logger.getLogger(CHPP_OAuth_Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CHPP_OAuth_Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * This method connects to CHPP in Hattrick and retrieves an specified Interface
     * @param access_token Client OAuth access token
     * @param secret_token Client OAuth secret token
     * @param url_interface URL to the CHPP interface to retrieve
     * @return an String with the response (XML format), null otherwise
     */
    public String launch_chpp_petition(String access_token, String secret_token, String url_interface) {
        try {
            consumer.setTokenWithSecret(access_token, secret_token);
            URL url = new URL(url_interface);
            HttpURLConnection request = (HttpURLConnection) url.openConnection();
            request.setRequestMethod(Constants.METHOD);
            consumer.sign(request);
            System.out.println("Sending request to Hattrick...");
            request.connect();
            System.out.println("Response: " + request.getResponseCode() + " " + request.getResponseMessage());

            if (String.valueOf(request.getResponseCode()).contains("200")) {
                return convertStreamToString(request.getInputStream());

            } else {
                System.out.println(convertStreamToString(request.getErrorStream()));
            }

            request.disconnect();
        } catch (MalformedURLException ex) {
            Logger.getLogger(CHPP_OAuth_Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | OAuthMessageSignerException | OAuthExpectationFailedException | OAuthCommunicationException ex) {
            Logger.getLogger(CHPP_OAuth_Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Converts an InputStream into a String
     *
     * @param is InputStream to convert
     * @return InputStream converted into a String
     * @throws IOException in case of failure
     */
    public static String convertStreamToString(InputStream is) throws IOException {
        if (is != null) {
            Writer writer = new StringWriter();
            char[] buffer = new char[1024];
            try {
                Reader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
                int n;
                while ((n = reader.read(buffer)) != -1) {
                    writer.write(buffer, 0, n);
                }
            } finally {
                is.close();
            }
            return writer.toString();
        } else {
            return "";
        }
    }

    /**
     * Main class for testing the library (empty)
     *
     * @deprecated
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }

}
