/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Enumeration;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.CustomStreamsSocket;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpInputStream;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpOutputStream;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.xml.sax.SAXException;
import org.zaproxy.zap.control.ControlOverrides;
import org.zaproxy.zap.extension.api.API;

public class ZapServlet extends HttpServlet {

    private final Logger logger = Logger.getLogger(ZapServlet.class);

    private static final long serialVersionUID = 3276343432698150320L;

    public void init() throws ServletException {

        ControlOverrides controlOverrides = new ControlOverrides();
        controlOverrides.setProxyPort(8080);
        controlOverrides.setProxyHost("localhost");
        // controlOverrides.setOrderedConfigs(getArgs().getOrderedConfigs());
        // controlOverrides.setExperimentalDb(getArgs().isExperimentalDb());

        // instantiating control singleton
        try {
            Constant.createInstance(controlOverrides);
        } catch (final Throwable e) {
            logger.error(e.getMessage(), e);
        }

        try {
            Model.getSingleton().init(controlOverrides);
        } catch (SAXException e) {
            logger.error(e.getMessage(), e);
            e.printStackTrace();
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
            e.printStackTrace();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            e.printStackTrace();
        }
        Model.getSingleton().getOptionsParam().setGUI(false);
        Control.initSingletonWithoutViewAndProxy(controlOverrides);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpRequestHeader requestHeader = new HttpRequestHeader();

        Socket inSocket = new Socket(request.getServerName(), request.getServerPort());
        BufferedInputStream bufferedInputStream =
                new BufferedInputStream(inSocket.getInputStream(), 2048);

        inSocket =
                new CustomStreamsSocket(inSocket, bufferedInputStream, inSocket.getOutputStream());

        HttpInputStream httpIn = new HttpInputStream(inSocket);
        HttpOutputStream httpOut = new HttpOutputStream(inSocket.getOutputStream());

        requestHeader.setSenderAddress(inSocket.getInetAddress());

        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String paramName = headerNames.nextElement();
            String paramValue = request.getHeader(paramName);
            requestHeader.setHeader(paramName, paramValue);
        }

        requestHeader.setMethod(request.getMethod());
        String Uri = request.getRequestURL() + "?" + request.getQueryString();
        URI uri = new URI(Uri, false);
        requestHeader.setURI(uri);

        HttpMessage msg = API.getInstance().handleApiRequest(requestHeader, httpIn, httpOut, true);
        // isRecursive(requestHeader) given as true for now.

        response.getWriter().print(msg.getResponseBody());
    }
}
