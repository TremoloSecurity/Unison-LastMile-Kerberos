/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.proxy.lastmile.kerberos;

import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthInfo;
import com.tremolosecurity.proxy.filter.HttpFilter;
import com.tremolosecurity.proxy.filter.HttpFilterChain;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.filter.HttpFilterRequest;
import com.tremolosecurity.proxy.filter.HttpFilterResponse;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.proxy.auth.AuthController;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.joda.time.DateTime;

import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.ExtendedGSSCredential;

public class KerberosLastMile implements HttpFilter {

	static Logger logger = Logger.getLogger(KerberosLastMile.class.getName());
	
    /**
     * Re-usable service Subject obtained by Kerberbos LoginContext
     * configured with java.login.conf
     */
    Subject serviceSubject;
    /** Re-usable service GSSCredentials in initiator only mode. */
    GSSCredential serviceCredentials;
	
    String uidAttributeName;
	String targetPrincipal;
	
	String tokenIdentifier;
	
	String keytabPath;
	String keytabPrincipal;
	
	
	public void doFilter(HttpFilterRequest request, HttpFilterResponse response,
			HttpFilterChain chain) throws Exception {
		
		String header = (String) request.getSession().getAttribute(this.tokenIdentifier);
        
        DateTime expires = (DateTime) request.getSession().getAttribute("UNISON_KRB5_EXPIRES");
		if (header == null || expires.isBeforeNow()) {
		
			AuthInfo userData = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL)).getAuthInfo();
			
			UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
			
			Attribute uid = userData.getAttribs().get(this.uidAttributeName);
			if (uid == null) {
				throw new Exception("Attribute " + this.uidAttributeName + " not present");
			}
			
			header = "Negotiate " + this.generateToken(uid.getValues().get(0), this.targetPrincipal,request.getSession());
			request.getSession().setAttribute(this.tokenIdentifier, header);
		}
		request.addHeader(new Attribute("Authorization",header));
		
		
		chain.nextFilter(request, response, chain);

	}

	public void filterResponseBinary(HttpFilterRequest arg0,
			HttpFilterResponse arg1, HttpFilterChain arg2, byte[] arg3, int arg4)
			throws Exception {
		

	}

	public void filterResponseText(HttpFilterRequest arg0,
			HttpFilterResponse arg1, HttpFilterChain arg2, StringBuffer arg3)
			throws Exception {
		

	}

	public void initFilter(HttpFilterConfig config) throws Exception {
		this.uidAttributeName = this.loadOption("uidAttributeName", config, false);
		this.targetPrincipal = this.loadOption("targetServicePrincipal", config, false);
		this.keytabPath = this.loadOption("keytabPath", config, false);
		this.keytabPrincipal = this.loadOption("keytabPrincipal", config, false);
		
		String pathToLoginConf = config.getConfigManager().getContext().getRealPath("/WEB-INF/login.conf");
		PrintWriter out = new PrintWriter(new FileOutputStream(pathToLoginConf));
		
		out.println("service {");
		out.println("  com.sun.security.auth.module.Krb5LoginModule required");
		out.println("  useKeyTab=true");
		out.println("  storeKey=true");
		out.println("  doNotPrompt=true");
		out.println("  keyTab=\"" + this.keytabPath + "\"");
		out.println("  principal=\"" + this.keytabPrincipal + "\";");
		out.println("};");
		out.flush();
		out.close();
		
		System.setProperty("java.security.auth.login.config", pathToLoginConf);
		
		
		this.tokenIdentifier = "UNISON_KRB5_LASTMILE_" + this.targetPrincipal;
		
		Subject initialSubject = this.doInitialLogin();
		logger.info("Initial Service Subject : '" + initialSubject + "'");
		
		
		
	}
	
	private String loadOption(String name,HttpFilterConfig cfg,boolean mask) throws Exception{
		if (cfg.getAttribute(name) == null) {
			throw new Exception(name + " is required");
		} else {
			String val = cfg.getAttribute(name).getValues().get(0); 
			if (! mask) {
				logger.info("Config " + name + "='" + val + "'");
			} else {
				logger.info("Config " + name + "='*****'");
			}
			
			return val;
		}
	}
	
	/**
     * Generate target user credentials thanks to S4U2self mechanism.
     *
     * @param someone target user
     * @return target user GSS credentials
     * @throws Exception if impersonation is not allowed for servicelogin
     */
    public GSSCredential impersonate(final String someone) throws Exception {
        try {
            GSSCredential creds = Subject.doAs(this.serviceSubject, new PrivilegedExceptionAction<GSSCredential>() {
	            public GSSCredential run() throws Exception {
	                GSSManager manager = GSSManager.getInstance();
	                if (serviceCredentials == null) {
                            serviceCredentials = manager.createCredential(GSSCredential.INITIATE_ONLY);
	                }
	                GSSName other = manager.createName(someone, GSSName.NT_USER_NAME);
	                return ((ExtendedGSSCredential)serviceCredentials).impersonate(other);
	                //return serviceCredentials; // alternative to skip impersonation (as intermediate test)
	            }
	        });
            return creds;
        } catch (PrivilegedActionException pae) {
            throw pae.getException();
        }
    }

    /**
     * Obtains a service context for a target SPN.
     *
     * @param target SPN to get context and token for
     * @param userCredentials target user credentials
     * @param mech GSS mech
     * @throws Exception in case of failure
     */
    public ExtendedGSSContext startAsClient(final String target,
                                            final GSSCredential userCredentials,
                                            final Oid mech)
        throws Exception {
        final Oid KRB5_PRINCIPAL_OID = new Oid("1.2.840.113554.1.2.2.1");
        ExtendedGSSContext context =
            Subject.doAs(this.serviceSubject, new PrivilegedExceptionAction<ExtendedGSSContext>() {
                    public ExtendedGSSContext run() throws Exception {
                        GSSManager manager = GSSManager.getInstance();
                        GSSName servicePrincipal = manager.createName(target, KRB5_PRINCIPAL_OID);
                        ExtendedGSSContext extendedContext =
                            (ExtendedGSSContext) manager.createContext(servicePrincipal,
                                                                       mech,
                                                                       userCredentials,
                                                                       GSSContext.DEFAULT_LIFETIME);
                        //extendedContext.requestMutualAuth(true);
                        //extendedContext.requestConf(true);
                        return extendedContext;
                    }
                });
        return context;
    }

    /**
     * Generate a context and TGS token for a target user
     *
     * @param targetUserName user to impersonate
     * @param targetService target service SPN
     * @return Base64 token
     * @throws Exception many thinks may fail
     */
    public String generateToken(String targetUserName, String targetService,HttpSession session) throws Exception {
        
        
        final Oid SPNEGO_OID = new Oid("1.3.6.1.5.5.2");

        // Get impersonated user credentials
        GSSCredential impersonatedUserCreds = impersonate(targetUserName);
        
        
        if (logger.isDebugEnabled()) {
        	logger.debug("Credentials for " + targetUserName + ": " + impersonatedUserCreds);
        }

        // Create context for target service
        ExtendedGSSContext context = startAsClient(targetService, impersonatedUserCreds, SPNEGO_OID);
        DateTime expires = new DateTime(DateTime.now().getMillis() + (1000L * context.getLifetime()));
        session.setAttribute("UNISON_KRB5_EXPIRES", expires);

        final byte[] token = context.initSecContext(new byte[0], 0, 0);
        
        if (!context.isEstablished()) {
            //throw new Exception("Context not established");
        }

        //if (logger.isDebugEnabled()) {
        	logger.info("Context srcName " + context.getSrcName());
            logger.info("Context targName " + context.getTargName());
            logger.info("Lifetome " + context.getLifetime());
            
            //logger.info(context.getDelegCred().getName());
            
        //}

        final String result = Base64.getEncoder().encodeToString(token);
        
        if (logger.isDebugEnabled()) {
        	logger.debug("Token " + Base64.getEncoder().encodeToString(token));
        }

        // Free context
        context.dispose();
        // Free impersonated user credentials
        impersonatedUserCreds.dispose();

        return result;
    }
	
	/**
     * Process JAAS login.
     * @throws LoginException
     */
    public Subject doInitialLogin() throws LoginException {
        // PasswordCallbackHandler is only useful if login.config keytab is out of order (no not provide login/password here)
        LoginContext lc = new LoginContext("service", new UserPasswordCallbackHandler("servicelogin","servicepassword"));
        lc.login();
        serviceSubject = lc.getSubject();
        return lc.getSubject();
    }
	
	
	/**
     * Required class to handle user/password authentication,
     * even if it is useless when keytab is defined in login.conf
     */
    class UserPasswordCallbackHandler implements CallbackHandler {
        private String username;
        private String password;

        public UserPasswordCallbackHandler(String u, String p) {
            this.username = u;
            this.password = p;
        }

        public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof NameCallback) {
                    NameCallback nc = (NameCallback)callbacks[i];
                    nc.setName(username);
                } else if (callbacks[i] instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback)callbacks[i];
                    pc.setPassword(password.toCharArray());
                } else throw new UnsupportedCallbackException
                           (callbacks[i], "Unrecognised callback");
            }
        }
    }

}
