package burp.Bootstrap;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 专门拿来做插件的全局变量共享的类
 */
public class GlobalVariableReader {
    private ConcurrentHashMap booleanMap;

    private ConcurrentHashMap siteScanMap;

    private ConcurrentHashMap issueMap;

    public GlobalVariableReader() {
        this.booleanMap = new ConcurrentHashMap<String, Boolean>();
        this.siteScanMap = new ConcurrentHashMap<String, Integer>();
        this.issueMap = new ConcurrentHashMap<String, Integer>();
    }

    public Map<String, Boolean> getBooleanMap() {
        return this.booleanMap;
    }

    public Boolean getBooleanData(String key) {
        return this.getBooleanMap().get(key);
    }

    public void putBooleanData(String key, Boolean b) {
        if (key == null || key.length() <= 0) {
            throw new IllegalArgumentException("key不能为空");
        }

        synchronized (this.getBooleanMap()) {
            this.getBooleanMap().put(key, b);
        }
    }

    public void delBooleanData(String key) {
        if (this.getBooleanMap().get(key) != null) {
            this.getBooleanMap().remove(key);
        }
    }

    /**
     * 获取某域名已被插件实际扫描(指纹探测)的次数
     */
    public Integer getSiteScan(String domain) {
        Integer v = (Integer) this.siteScanMap.get(domain);
        return v == null ? Integer.valueOf(0) : v;
    }

    /**
     * 某域名被插件实际扫描一次(计数+1), 返回新的次数
     */
    public int incrementSiteScan(String domain) {
        synchronized (this.siteScanMap) {
            Integer cur = (Integer) this.siteScanMap.get(domain);
            int next = (cur == null ? 0 : cur) + 1;
            this.siteScanMap.put(domain, Integer.valueOf(next));
            return next;
        }
    }

    /**
     * 获取某站点某类问题(按问题名) 在当前开关周期内已上报的次数
     */
    public Integer getSiteIssue(String domain, String issueName) {
        Integer v = (Integer) this.issueMap.get(domain + "::" + issueName);
        return v == null ? Integer.valueOf(0) : v;
    }

    /**
     * 某站点某类问题上报次数(计数+1)
     */
    public int incrementSiteIssue(String domain, String issueName) {
        String key = domain + "::" + issueName;
        synchronized (this.issueMap) {
            Integer cur = (Integer) this.issueMap.get(key);
            int next = (cur == null ? 0 : cur) + 1;
            this.issueMap.put(key, Integer.valueOf(next));
            return next;
        }
    }

    /**
     * 清零所有站点的扫描计数与问题上报计数(插件开关状态每次变化时调用)
     */
    public void resetSiteScan() {
        synchronized (this.siteScanMap) {
            this.siteScanMap.clear();
        }
        synchronized (this.issueMap) {
            this.issueMap.clear();
        }
    }
}