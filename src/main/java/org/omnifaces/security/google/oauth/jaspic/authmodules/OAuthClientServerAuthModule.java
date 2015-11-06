package org.omnifaces.security.google.oauth.jaspic.authmodules;

import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.jaspic.Utils.encodeURL;
import static org.omnifaces.security.jaspic.Utils.getBaseURL;
import static org.omnifaces.security.jaspic.core.Jaspic.isAuthenticationRequest;

import java.util.logging.Logger;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.security.cdi.Beans;
import org.omnifaces.security.google.oauth.jaspic.user.OAuthClientAuthenticator;
import org.omnifaces.security.jaspic.core.HttpMsgContext;
import org.omnifaces.security.jaspic.core.HttpServerAuthModule;
import org.omnifaces.security.jaspic.exceptions.ProfileIncompleteException;
import org.omnifaces.security.jaspic.exceptions.RegistrationException;
import org.omnifaces.security.jaspic.request.RequestDataDAO;
import org.omnifaces.security.jaspic.request.StateCookieDAO;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.TokenResponse;

public class OAuthClientServerAuthModule extends HttpServerAuthModule {

	private static final Logger logger = Logger.getLogger(OAuthClientServerAuthModule.class.getName());

	private final AuthorizationCodeFlow authorizationCodeFlow;

	public static final String SOCIAL_PROFILE = "omnisecurity.socialProfile";
	public static final String SOCIAL_MANAGER = "omnisecurity.socialManager";

	public static final String USE_SESSIONS = "useSessions";
	public static final String CALLBACK_URL = "callbackUrl";
	public static final String PROFILE_INCOMPLETE_URL = "profileIncompleteUrl";
	public static final String REGISTRATION_ERROR_URL = "registrationErrorUrl";

	public boolean useSessions;
	public String callbackURL;
	public String profileIncompleteUrl;
	public String registrationErrorUrl;

	private StateCookieDAO stateCookieDAO = new StateCookieDAO();
	private final RequestDataDAO requestDAO = new RequestDataDAO();

	public OAuthClientServerAuthModule(AuthorizationCodeFlow authorizationCodeFlow) {
		this.authorizationCodeFlow = authorizationCodeFlow;
	}

	@Override
	public void initializeModule(HttpMsgContext httpMsgContext) {
		useSessions = Boolean.valueOf(httpMsgContext.getModuleOption(USE_SESSIONS));
		callbackURL = httpMsgContext.getModuleOption(CALLBACK_URL);
		profileIncompleteUrl = httpMsgContext.getModuleOption(PROFILE_INCOMPLETE_URL);
		registrationErrorUrl = httpMsgContext.getModuleOption(REGISTRATION_ERROR_URL);
	}

	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext)
	        throws AuthException {
		if (isLoginRequest(request, response, httpMsgContext)) {
			return SEND_CONTINUE;
		}

		try {
			// Check if the user has arrived back from the OAuth provider

			if (isCallbackRequest(request, response, httpMsgContext)) {
				return doOAuthLogin(request, response, httpMsgContext);
			}

		}
		catch (Exception e) {
			throw (AuthException) new AuthException().initCause(e);
		}

		return SUCCESS;
	}

	private boolean isLoginRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {
		// TODO Auto-generated method stub

		if (isAuthenticationRequest(request)) {
			try {
				// TODO deal with state and other extra parameters once bug in OmniSecurity is fixed

				String authorizationUrl = authorizationCodeFlow.newAuthorizationUrl()
				                                               .setRedirectUri(getBaseURL(request) + callbackURL)
				                                               .build();
				response.sendRedirect(authorizationUrl);

				return true;
			}
			catch (Exception e) {
				throw (AuthException)new AuthException().initCause(e);
			}
		}

		return false;
	}

	private boolean isCallbackRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {
		if (request.getRequestURI().equals(callbackURL) && request.getParameter("code") != null) {

			return true;
			// TODO Enable state checking
//			if (!isEmpty(request.getParameter("state"))) {
//				try {
//					String state = request.getParameter("state");
//					Cookie cookie = stateCookieDAO.get(request);
//
//					if (cookie != null && state.equals(cookie.getValue())) {
//						return true;
//					} else {
//						logger.log(WARNING,
//							"State parameter provided with callback URL, but did not match cookie. " +
//							"State param value: " + state + " " +
//							"Cookie value: " + (cookie == null? "<no cookie>" : cookie.getValue())
//						);
//					}
//				} finally {
//					stateCookieDAO.remove(request, response);
//				}
//			}
		}

		return false;
	}

	private AuthStatus doOAuthLogin(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {

		String parameter = request.getParameter("code");

		TokenResponse tokenResponse = authorizationCodeFlow.newTokenRequest(parameter).setRedirectUri(getBaseURL(request) + callbackURL).execute();
		OAuthClientAuthenticator authenticator = Beans.getReference(OAuthClientAuthenticator.class);

		try {
			if (authenticator.authenticateOrRegister(tokenResponse)) {
				httpMsgContext.registerWithContainer(authenticator.getUserName(), authenticator.getApplicationRoles());

				if (!useSessions) {
					request.getSession().removeAttribute(SOCIAL_PROFILE);
				}

				return SUCCESS;
			}
		}
		catch (ProfileIncompleteException e) {
			if (e.getReason() != null && !request.getServletPath().startsWith(profileIncompleteUrl)) {
				response.sendRedirect(profileIncompleteUrl);

				return SEND_CONTINUE;
			}

			return SUCCESS; // DO NOTHING, slightly different from SUCCESS
		}
		catch (RegistrationException e) {
			if (e.getReason() != null) {
				request.getSession().setAttribute(SOCIAL_PROFILE, null);
				response.sendRedirect(registrationErrorUrl + "?failure-reason=" + encodeURL(e.getReason()));
			}
		}

		return SEND_FAILURE;
	}
}
