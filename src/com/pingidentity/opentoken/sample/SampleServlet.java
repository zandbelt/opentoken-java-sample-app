package com.pingidentity.opentoken.sample;

import java.io.*;
import java.net.URLEncoder;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.*;

import com.pingidentity.opentoken.Agent;
import com.pingidentity.opentoken.TokenException;

public class SampleServlet extends HttpServlet {

	private static final long serialVersionUID = 5984011966182486047L;

	private static final String USER_INFO = "USER_INFO";
	private static final String CONFIGURATION_FILENAME = "/sample.properties";
	private static final String AGENT_CONFIGURATION_FILENAME = "/agent-config.txt";

	/*
	 * get the application's configuration from a properties file
	 */
	protected Properties getConfiguration(HttpServletRequest request,
			String path) throws IOException {
		InputStream stream = request.getServletContext().getResourceAsStream(
				path);
		Properties props = new Properties();
		props.load(stream);
		return props;
	}

	/*
	 * get the user info stored in the session
	 */
	@SuppressWarnings("unchecked")
	protected Map<String, String> getUserInfoFromSession(
			HttpServletRequest request) {
		HttpSession session = request.getSession();
		return (Map<String, String>) session.getAttribute(USER_INFO);
	}

	/*
	 * handle an existing session by printing out user information
	 */
	protected void handleExistingSession(HttpServletRequest request,
			HttpServletResponse response, Properties props,
			Map<String, String> userInfo) throws IOException {
		if (userInfo == null) return;
		// String username = (String)userInfo.get(Agent.TOKEN_SUBJECT);
		response.getWriter().print("<html><head><title>");
		response.getWriter().print(props.getProperty("title"));
		response.getWriter().print("</title></head><body>");
		response.getWriter().print(
				"<h3>" + props.getProperty("title") + "</h3>");
		response.getWriter().print("<p><table border=\"1\">");
		for (String key : userInfo.keySet()) {
			response.getWriter().print(
					"<tr><td>" + key + "</td><td>" + userInfo.get(key)
							+ "</td></tr>");
		}
		response.getWriter().print("</table></p>");
		response.getWriter().print("</body></html>");
		response.getWriter().flush();
	}

	@SuppressWarnings("unchecked")
	protected Map<String, String> readOpenToken(HttpServletRequest request)
			throws IOException {
		Map<String, String> userInfo = null;
		Agent agent = new Agent(request.getServletContext()
				.getResourceAsStream(AGENT_CONFIGURATION_FILENAME));
		try {
			userInfo = agent.readToken(request);
		} catch (TokenException e) {
			e.printStackTrace();
			throw new IOException(e);
		}
		return userInfo;
	}

	protected Map<String, String> handleUnauthenticatedSession(HttpServletRequest request,
			HttpServletResponse response, Properties props) throws IOException {
		// try and read an OpenToken from the incoming request
		Map<String, String> userInfo = readOpenToken(request);
		if (userInfo == null) {
			// send the user off to PingFederate to authenticate
			StringBuffer url = new StringBuffer(props.getProperty("startsso"));
			url.append("?");
			url.append("SpSessionAuthnAdapterId="
					+ URLEncoder.encode(props.getProperty("adapterid"), "UTF-8"));
			url.append("&");
			url.append("TargetResource="
					+ URLEncoder.encode(getCurrentURL(request), "UTF-8"));
			if (props.getProperty("params") != null) {
				url.append("&" + props.getProperty("params"));
			}
			response.sendRedirect(url.toString());
		} else {
			// received OpenToken, set it in the session
			request.getSession().setAttribute(USER_INFO, userInfo);
		}
		return userInfo;
	}

	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		Properties props = getConfiguration(request, CONFIGURATION_FILENAME);
		Map<String, String> userInfo = getUserInfoFromSession(request);
		if (userInfo == null)
			userInfo = handleUnauthenticatedSession(request, response, props);
		handleExistingSession(request, response, props, userInfo);
	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

	protected String getCurrentURL(HttpServletRequest request) {
		StringBuffer url = new StringBuffer();
		url.append(request.getScheme());
		url.append("://");
		url.append(request.getServerName());
		if (((request.getScheme().equals("http")) && (request.getServerPort() != 80))
				|| ((request.getScheme().equals("https")) && (request
						.getServerPort() != 443))) {
			url.append(":");
			url.append(request.getServerPort());
		}
		url.append(request.getRequestURI());
		if ((request.getQueryString() != null)
				&& (!request.getQueryString().equals(""))) {
			url.append("?");
			url.append(request.getQueryString());
		}
		return url.toString();
	}
}
