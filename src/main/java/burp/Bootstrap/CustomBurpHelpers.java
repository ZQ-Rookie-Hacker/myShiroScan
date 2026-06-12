package burp.Bootstrap;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.*;

public class CustomBurpHelpers {
    public static final String INTERNAL_PROBE_HEADER = "X-BurpShiroPassiveScan-Probe";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public CustomBurpHelpers(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * 获取-插件运行路径
     *
     * @return
     */
    public String getExtensionFilePath() {
        String extensionFilename = this.callbacks.getExtensionFilename();
        if (extensionFilename == null || extensionFilename.trim().length() == 0) {
            return "";
        }

        int lastIndex = Math.max(
                extensionFilename.lastIndexOf(File.separator),
                Math.max(extensionFilename.lastIndexOf('/'), extensionFilename.lastIndexOf('\\'))
        );

        if (lastIndex < 0) {
            return "";
        }

        return extensionFilename.substring(0, lastIndex + 1);
    }

    /**
     * 发送探测请求。
     *
     * 新版 Burp 在 HTTP/2/新版网络栈场景下，直接使用 makeHttpRequest(IHttpService, byte[])
     * 复用原始请求偶尔会出现探测流量发不出去、协议不兼容或请求行异常的问题。
     * 这里统一把请求规范成老 Extender API 最稳定的 HTTP/1.1 报文格式，然后使用
     * host/port/useHttps 重载发包，保持原有扫描逻辑不变，只调整发包兼容性。
     *
     * @param baseRequestResponse 原始请求响应，用于提取目标服务
     * @param request             需要发送的新请求
     * @return IHttpRequestResponse
     */
    public IHttpRequestResponse makeHttpRequest(IHttpRequestResponse baseRequestResponse, byte[] request) {
        IHttpService httpService = baseRequestResponse.getHttpService();
        boolean useHttps = "https".equalsIgnoreCase(httpService.getProtocol());
        byte[] normalizedRequest = this.normalizeHttpRequest(request, httpService);
        byte[] response = this.callbacks.makeHttpRequest(
                httpService.getHost(),
                httpService.getPort(),
                useHttps,
                normalizedRequest
        );
        return new CustomHttpRequestResponse(normalizedRequest, response, httpService);
    }

    /**
     * 将 Burp 提供的新请求规范成 HTTP/1.1 raw request。
     */
    private byte[] normalizeHttpRequest(byte[] request, IHttpService httpService) {
        IRequestInfo requestInfo = this.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<String>(requestInfo.getHeaders());

        if (headers.size() > 0) {
            String requestLine = headers.get(0);
            if (requestLine.endsWith(" HTTP/2") || requestLine.endsWith(" HTTP/2.0")) {
                headers.set(0, requestLine.substring(0, requestLine.lastIndexOf(' ')) + " HTTP/1.1");
            }
        }

        boolean hasHostHeader = false;
        for (String header : headers) {
            if (header.toLowerCase().startsWith("host:")) {
                hasHostHeader = true;
                break;
            }
        }

        if (!hasHostHeader) {
            headers.add(1, "Host: " + this.buildHostHeader(httpService));
        }

        boolean hasInternalProbeHeader = false;
        for (String header : headers) {
            if (header.toLowerCase().startsWith(INTERNAL_PROBE_HEADER.toLowerCase() + ":")) {
                hasInternalProbeHeader = true;
                break;
            }
        }
        if (!hasInternalProbeHeader) {
            headers.add(INTERNAL_PROBE_HEADER + ": 1");
        }

        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        return this.helpers.buildHttpMessage(headers, body);
    }

    private String buildHostHeader(IHttpService httpService) {
        String host = httpService.getHost();
        int port = httpService.getPort();
        String protocol = httpService.getProtocol();

        if (("http".equalsIgnoreCase(protocol) && port == 80)
                || ("https".equalsIgnoreCase(protocol) && port == 443)) {
            return host;
        }
        return host + ":" + port;
    }

    /**
     * 获取请求的Body内容
     *
     * @return String
     */
    public String getHttpRequestBody(byte[] request) {
        IRequestInfo requestInfo = this.helpers.analyzeRequest(request);

        int httpRequestBodyOffset = requestInfo.getBodyOffset();
        int httpRequestBodyLength = request.length - httpRequestBodyOffset;

        String httpRequestBody = null;
        try {
            httpRequestBody = new String(request, httpRequestBodyOffset, httpRequestBodyLength, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return httpRequestBody;
    }

    /**
     * 获取响应的Body内容
     *
     * @return String
     */
    public String getHttpResponseBody(byte[] response) {
        IResponseInfo responseInfo = this.helpers.analyzeResponse(response);

        int httpResponseBodyOffset = responseInfo.getBodyOffset();
        int httpResponseBodyLength = response.length - httpResponseBodyOffset;

        String httpResponseBody = null;
        try {
            httpResponseBody = new String(response, httpResponseBodyOffset, httpResponseBodyLength, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return httpResponseBody;
    }
}