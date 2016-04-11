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

	@SuppressWarnings("unchecked")
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		InputStream stream = request.getServletContext().getResourceAsStream("/sample.properties");
		Properties props = new Properties();
		props.load(stream);
		
		HttpSession session = request.getSession();
		
		Map<String, String> userInfo = (Map<String, String>)session.getAttribute("userInfo");
		
		if (userInfo == null) {

			try {
				Agent agent = new Agent(request.getServletContext().getResourceAsStream("/agent-config.txt"));				 
				userInfo = agent.readToken(request);
				if(userInfo != null) {
				   session.setAttribute("userInfo", userInfo);
				} else {
					StringBuffer url = new StringBuffer(props.getProperty("startsso"));
					url.append("?");
					url.append("SpSessionAuthnAdapterId=" + URLEncoder.encode(props.getProperty("adapterid"), "UTF-8"));
					url.append("&");
					url.append("TargetResource=" + URLEncoder.encode(getCurrentURL(request), "UTF-8"));
					if (props.getProperty("params") != null) {
						url.append("&" + props.getProperty("params"));
					}
					response.sendRedirect(url.toString());
					return;
				}
			} catch(TokenException e) {
				e.printStackTrace();
				throw new IOException(e);
			}
		}
		
		//String username = (String)userInfo.get(Agent.TOKEN_SUBJECT);

		response.getWriter().print("<html><head><title>");
		response.getWriter().print(props.getProperty("title"));
		response.getWriter().print("</title></head><body>");
		response.getWriter().print("<h3>" + props.getProperty("title") + "</h3>");
		response.getWriter().print("<p><table border=\"1\">");
		for (String key : userInfo.keySet()) {
			response.getWriter().print("<tr><td>" + key + "</td><td>" + userInfo.get(key) + "</td></tr>");
		}
 		response.getWriter().print("</table></p>");
		response.getWriter().print("</body></html>");
		response.getWriter().flush();
		
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
	
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}
}
