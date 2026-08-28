package burp.Bootstrap;

import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import org.yaml.snakeyaml.DumperOptions;

import org.yaml.snakeyaml.Yaml;

import burp.IBurpExtenderCallbacks;

public class YamlReader {
    private static YamlReader instance;

    private static Map<String, Map<String, Object>> properties = new HashMap<>();

    /**
     * 配置文件的持久化路径
     * 与加载时优先使用的 "可编辑的 jar 外 resources/config.yml" 保持一致
     */
    private String resourcesConfigPath;

    /**
     * 用于保存失败时路由错误信息到 Burp 的 Errors 面板
     */
    private final IBurpExtenderCallbacks callbacks;

    private YamlReader(IBurpExtenderCallbacks callbacks) throws FileNotFoundException {
        this.callbacks = callbacks;
        CustomBurpHelpers customBurpHelpers = new CustomBurpHelpers(callbacks);
        String c = customBurpHelpers.getExtensionFilePath() + "resources/config.yml";
        this.resourcesConfigPath = c;
        File f = new File(c);

        InputStream configInputStream;
        if (f.exists() && f.isFile()) {
            // Keep the original behaviour: prefer the editable external config next to the extension jar.
            configInputStream = new FileInputStream(f);
        } else {
            // Newer Burp versions are commonly used by loading only the jar.
            // In that case, fall back to the config packaged in the jar instead of failing on startup.
            configInputStream = YamlReader.class.getClassLoader().getResourceAsStream("config.yml");
            if (configInputStream == null) {
                configInputStream = YamlReader.class.getClassLoader().getResourceAsStream("resources/config.yml");
            }
            if (configInputStream == null) {
                throw new FileNotFoundException("config.yml not found in " + c + " or extension jar resources");
            }
        }

        properties = new Yaml().load(configInputStream);
    }

    public static synchronized YamlReader getInstance(IBurpExtenderCallbacks callbacks) {
        if (instance == null) {
            try {
                instance = new YamlReader(callbacks);
            } catch (FileNotFoundException e) {
                e.printStackTrace(new PrintWriter(callbacks.getStderr(), true));
            }
        }
        return instance;
    }

    /**
     * 获取yaml属性
     * 可通过 "." 循环调用
     * 例如这样调用: YamlReader.getInstance().getValueByKey("a.b.c.d")
     *
     * @param key
     * @return
     */
    public Object getValueByKey(String key) {
        String separator = ".";
        String[] separatorKeys = null;
        if (key.contains(separator)) {
            separatorKeys = key.split("\\.");
        } else {
            return properties.get(key);
        }
        Map<String, Map<String, Object>> finalValue = new HashMap<>();
        for (int i = 0; i < separatorKeys.length - 1; i++) {
            if (i == 0) {
                finalValue = (Map) properties.get(separatorKeys[i]);
                continue;
            }
            if (finalValue == null) {
                break;
            }
            finalValue = (Map) finalValue.get(separatorKeys[i]);
        }
        return finalValue == null ? null : finalValue.get(separatorKeys[separatorKeys.length - 1]);
    }

    public String getString(String key) {
        return String.valueOf(this.getValueByKey(key));
    }

    public String getString(String key, String defaultValue) {
        if (null == this.getValueByKey(key)) {
            return defaultValue;
        }
        return String.valueOf(this.getValueByKey(key));
    }

    public Boolean getBoolean(String key) {
        return (boolean) this.getValueByKey(key);
    }

    public Integer getInteger(String key) {
        return (Integer) this.getValueByKey(key);
    }

    public double getDouble(String key) {
        return (double) this.getValueByKey(key);
    }

    public List<String> getStringList(String key) {
        return (List<String>) this.getValueByKey(key);
    }

    public LinkedHashMap<String, Boolean> getLinkedHashMap(String key) {
        return (LinkedHashMap<String, Boolean>) this.getValueByKey(key);
    }

    /**
     * 获取配置文件的持久化路径
     *
     * @return 绝对路径字符串
     */
    public String getConfigFilePath() {
        return this.resourcesConfigPath;
    }

    /**
     * 通过 "." 分隔的 key 修改内存中的配置值
     * 例如: setValueByKey("scan.siteScanNumber", 10)
     *
     * @param key   配置项路径
     * @param value 新的值
     */
    public void setValueByKey(String key, Object value) {
        String[] keys = key.split("\\.");
        if (keys.length <= 0) {
            return;
        }

        Map<String, Object> current = (Map<String, Object>) (Map) properties;

        for (int i = 0; i < keys.length - 1; i++) {
            Object next = current.get(keys[i]);
            if (next instanceof Map) {
                current = (Map<String, Object>) next;
            } else {
                Map<String, Object> newMap = new LinkedHashMap<>();
                current.put(keys[i], newMap);
                current = newMap;
            }
        }

        current.put(keys[keys.length - 1], value);
    }

    /**
     * 将当前内存中的配置以 YAML 格式写回 config.yml
     * 写入路径与加载时优先使用的 "可编辑的 jar 外 resources/config.yml" 一致：
     * - 若该文件已存在则覆盖
     * - 若不存在则自动创建目录与文件（之后插件启动会优先加载它）
     *
     * 注: 写回会重建整个配置文件，原文件中的注释将被移除。
     *
     * @return true = 保存成功, false = 保存失败
     */
    public synchronized boolean save() {
        File file = new File(this.resourcesConfigPath);
        try {
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            DumperOptions options = new DumperOptions();
            options.setIndent(2);
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

            Yaml yaml = new Yaml(options);
            String dump = yaml.dump(properties);

            try (FileOutputStream fileOutputStream = new FileOutputStream(file);
                 OutputStreamWriter writer = new OutputStreamWriter(fileOutputStream, StandardCharsets.UTF_8)) {
                writer.write(dump);
                writer.flush();
            }
            return true;
        } catch (IOException e) {
            if (this.callbacks != null) {
                e.printStackTrace(new PrintWriter(this.callbacks.getStderr(), true));
            } else {
                e.printStackTrace(new PrintWriter(System.err, true));
            }
            return false;
        }
    }
}