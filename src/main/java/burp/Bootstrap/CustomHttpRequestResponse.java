package burp.Bootstrap;

import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * Lightweight IHttpRequestResponse wrapper used for requests sent through
 * IBurpExtenderCallbacks.makeHttpRequest(host, port, useHttps, request), whose
 * legacy overload returns only the response bytes.
 */
public class CustomHttpRequestResponse implements IHttpRequestResponse {
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private IHttpService httpService;

    public CustomHttpRequestResponse(byte[] request, byte[] response, IHttpService httpService) {
        this.request = request;
        this.response = response;
        this.httpService = httpService;
    }

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public void setRequest(byte[] message) {
        this.request = message;
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }

    @Override
    public void setResponse(byte[] message) {
        this.response = message;
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return this.highlight;
    }

    @Override
    public void setHighlight(String color) {
        this.highlight = color;
    }

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
}
