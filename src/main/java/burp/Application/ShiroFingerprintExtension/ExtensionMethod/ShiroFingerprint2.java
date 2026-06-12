package burp.Application.ShiroFingerprintExtension.ExtensionMethod;

import burp.*;
import burp.Application.ShiroFingerprintExtension.ExtensionInterface.AShiroFingerprintExtension;
import burp.Bootstrap.CustomBurpHelpers;
import burp.Bootstrap.YamlReader;

import java.io.PrintWriter;
import java.net.URL;

public class ShiroFingerprint2 extends AShiroFingerprintExtension {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private YamlReader yamlReader;

    private CustomBurpHelpers customBurpHelpers;

    private IHttpRequestResponse baseRequestResponse;

    private String rememberMeCookieValue = "2";

    public ShiroFingerprint2(IBurpExtenderCallbacks callbacks, YamlReader yamlReader, IHttpRequestResponse baseRequestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.yamlReader = yamlReader;
        this.customBurpHelpers = new CustomBurpHelpers(callbacks);

        this.baseRequestResponse = baseRequestResponse;

        this.setExtensionName("ShiroFingerprint2");

        this.runConditionCheck();
    }

    /**
     * 原始请求响应返回 cookie 的 value 带了 deleteMe 则进入该流程
     */
    private void runConditionCheck() {
        for (ICookie c : this.helpers.analyzeResponse(this.baseRequestResponse.getResponse()).getCookies()) {
            if (c.getValue().equals("deleteMe")) {
                this.registerExtension();
                break;
            }
        }
    }

    public void runExtension() {
        if (!this.isRunExtension()) {
            return;
        }

        // 先保存一个基础的请求响应
        this.setHttpRequestResponse(this.baseRequestResponse);

        for (ICookie c : this.helpers.analyzeResponse(this.baseRequestResponse.getResponse()).getCookies()) {
            if (c.getValue().equals("deleteMe")) {
                this.setShiroFingerprint();

                // 通过返回包的key重新构造一个请求发过去
                // 这样二次确认过的请求响应, 可以获得最真实的结果
                IHttpRequestResponse newHttpRequestResponse = this.getNewHttpRequestResponse(
                        c.getName(),
                        this.rememberMeCookieValue);

                // 二次确认的请求确定是shiro框架了
                // 保存这个最真实的结果, 覆盖上面那个基础的请求响应
                this.setHttpRequestResponse(newHttpRequestResponse);

                this.setRequestDefaultRememberMeCookieName(c.getName());
                this.setRequestDefaultRememberMeCookieValue(this.rememberMeCookieValue);

                this.setResponseDefaultRememberMeCookieName(c.getName());
                this.setResponseDefaultRememberMeCookieValue(c.getValue());
                break;
            }
        }
    }

    /**
     * 获取新的http请求响应
     *
     * @param rememberMeCookieName
     * @param rememberMeCookieValue
     * @return IHttpRequestResponse
     */
    private IHttpRequestResponse getNewHttpRequestResponse(String rememberMeCookieName, String rememberMeCookieValue) {
        IParameter newParameter = this.helpers.buildParameter(
                rememberMeCookieName,
                rememberMeCookieValue,
                (byte) 2);
        byte[] newRequest = this.helpers.updateParameter(this.baseRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse newHttpRequestResponse = this.customBurpHelpers.makeHttpRequest(this.baseRequestResponse, newRequest);
        return newHttpRequestResponse;
    }

    @Override
    public IScanIssue export() {
        if (!this.isRunExtension()) {
            return null;
        }

        if (!this.isShiroFingerprint()) {
            return null;
        }

        IHttpRequestResponse baseHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(baseHttpRequestResponse).getUrl();

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
                new IHttpRequestResponse[]{baseHttpRequestResponse},
                baseHttpRequestResponse.getHttpService()
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

        IHttpRequestResponse baseHttpRequestResponse = this.getHttpRequestResponse();
        URL baseHttpRequestUrl = this.helpers.analyzeRequest(baseHttpRequestResponse).getUrl();
        String baseHttpRequestMethod = this.helpers.analyzeRequest(baseHttpRequestResponse.getRequest()).getMethod();
        int baseHttpResponseStatusCode = this.helpers.analyzeResponse(baseHttpRequestResponse.getResponse()).getStatusCode();

        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println(String.format("[Shiro] fingerprint found | %s | %s | %s | status=%d | cookie=%s=%s -> %s=%s",
                this.getExtensionName(),
                baseHttpRequestMethod,
                baseHttpRequestUrl,
                baseHttpResponseStatusCode,
                this.getRequestDefaultRememberMeCookieName(),
                this.getRequestDefaultRememberMeCookieValue(),
                this.getResponseDefaultRememberMeCookieName(),
                this.getResponseDefaultRememberMeCookieValue()));
    }
}
