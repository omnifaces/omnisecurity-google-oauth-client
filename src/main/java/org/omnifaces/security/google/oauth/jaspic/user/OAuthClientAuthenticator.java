package org.omnifaces.security.google.oauth.jaspic.user;

import org.omnifaces.security.jaspic.exceptions.ProfileIncompleteException;
import org.omnifaces.security.jaspic.exceptions.RegistrationException;
import org.omnifaces.security.jaspic.user.Authenticator;

import com.google.api.client.auth.oauth2.TokenResponse;

public interface OAuthClientAuthenticator extends Authenticator {

	boolean authenticateOrRegister(TokenResponse tokenResponse) throws RegistrationException, ProfileIncompleteException;

}
