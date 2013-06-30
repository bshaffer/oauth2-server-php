Test your server with Google OAuth 2.0 Playground
-------------------------------------------------

Once you've set up your server on the wild internet, you'll want to check that it works with an independent client.
One way to do this is using the [Google OAuth 2.0 Playground](https://developers.google.com/oauthplayground/).

Assuming that you've set up an authorize controller, you can test it out as follows:

  1. Navigate to the Playground using the above link.

  2. Click the settings button in the top-right corner.

  3. Select "Server-side" for "OAuth flow", and "Custom" for "OAuth endpoints".

  4. In the Authorization endpoint, enter the URL of your Authorize Controller (such as https://domain.com/authorize.php).

  5. In the Token endpoint, enter the URL of your Token Controller (such as https://domain.com/token.php).

  6. Select "Authorization header w/ Bearer prefix" for the Access token location.

  7. Enter the client ID and secret (testclient and testpass if using the previous documentation example).

  8. Enter "basic" in the text box on the left and click "Authorize APIs". You should be taken to your website where you can authorize the request, after which you should be returned to the Playground.

  9. Click "Exchange authorization code for tokens" to receive a token (you'll need to do this within 30 seconds).

  10. The response on the right should show the access token. Enter the URL of your resource page (such as https://domain.com/resource.php).

  11. Add any optional parameters you want, and click "Send the request". If you've used the same code as previously you should see the same response:

```json
{"success":true,"message":"You accessed my APIs!"}
```
