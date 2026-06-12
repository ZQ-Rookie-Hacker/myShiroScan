package burp.Application.ShiroFingerprintExtension.ExtensionMethod;

import burp.*;
import burp.Application.ShiroFingerprintExtension.ExtensionInterface.AShiroFingerprintExtension;
import burp.Bootstrap.CustomBurpHelpers;
import burp.Bootstrap.YamlReader;

import java.io.PrintWriter;
import java.net.URL;

public class ShiroFingerprint1 extends AShiroFingerprintExtension {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private YamlReader yamlReader;

    private CustomBurpHelpers customBurpHelpers;

    private IHttpRequestResponse baseRequestResponse;

    private String rememberMeCookieName = "rememberMe";
    private String rememberMeCookieValue = "1";

    public ShiroFingerprint1(IBurpExtenderCallbacks callbacks, YamlReader yamlReader, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.yamlReader = yamlReader;
        this.customBurpHelpers = new CustomBurpHelpers(callbacks);

        this.baseRequestResponse = baseRequestResponse;

        this.setExtensionName("ShiroFingerprint1");

        this.runConditionCheck();
    }

    private void runConditionCheck() {
        this.registerExtension();
    }

    public void runExtension() {
        if (!this.isRunExtension()) {
            return;
        }

        IParameter newParameter = this.helpers.buildParameter(this.rememberMeCookieName, this.rememberMeCookieValue, (byte) 2);
        byte[] newRequest = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = this.customBurpHelpers.makeHttpRequest(this.baseRequestResponse, newRequest);

        this.setHttpRequestResponse(newHttpRequestResponse);

        for (ICookie c : this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getCookies()) {
            if (c.getName().equals(this.rememberMeCookieName)) {
                this.setShiroFingerprint();

                this.setRequestDefaultRememberMeCookieName(this.rememberMeCookieName);
                this.setRequestDefaultRememberMeCookieValue(this.rememberMeCookieValue);

                this.setResponseDefaultRememberMeCookieName(c.getName());
                this.setResponseDefaultRememberMeCookieValue(c.getValue());
                break;
            }
        }
    }

    @Override
    public IScanIssue export() {
        if (!this.isRunExtension()) {
            return null;
        }

        if (!this.isShiroFingerprint()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>============ShiroFingerprintDetail============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("RequestCookiePayload: %s=%s <br/>",
                this.getRequestDefaultRememberMeCookieName(),
                this.getRequestDefaultRememberMeCookieValue());
        String str4 = String.format("ResponseReturnCookie: %s=%s <br/>",
                this.getResponseDefaultRememberMeCookieName(),
                this.getResponseDefaultRememberMeCookieValue());
        String str5 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5;

        String shiroFingerprintIssueName = this.yamlReader.getString("application.shiroFingerprintExtension.config.issueName");

        return new CustomScanIssue(
                newHttpRequestUrl,
                shiroFingerprintIssueName,
                0,
                "Information",
                "Certain",
                null,
                null,
                detail,
                null,
                new IHttpRequestResponse[]{newHttpRequestResponse},
                newHttpRequestResponse.getHttpService()
        );
    }

    @Override
    public void consoleExport() {
        if (!this.isRunExtension()) {
            return;
        }

        if (!this.isShiroFingerprint()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        String newHttpRequestMethod = this.helpers.analyzeRequest(newHttpRequestResponse.getRequest()).getMethod();
        int newHttpResponseStatusCode = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode();

        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println(String.format("[Shiro] fingerprint found | %s | %s | %s | status=%d | cookie=%s=%s -> %s=%s",
                this.getExtensionName(),
                newHttpRequestMethod,
                newHttpRequestUrl,
                newHttpResponseStatusCode,
                this.getRequestDefaultRememberMeCookieName(),
                this.getRequestDefaultRememberMeCookieValue(),
                this.getResponseDefaultRememberMeCookieName(),
                this.getResponseDefaultRememberMeCookieValue()));
    }
}
