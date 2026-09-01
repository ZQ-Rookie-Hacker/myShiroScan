package burp.Ui;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import burp.IBurpExtenderCallbacks;
import burp.Bootstrap.YamlReader;

public class BaseSettingTag {
    private YamlReader yamlReader;

    private JLabel statusLabel;

    /**
     * 结构化配置字段集合
     */
    private final List<ConfigField> fields = new ArrayList<>();

    /**
     * 字典根目录: 与 config.yml 同级目录下的 dictionaries 文件夹
     * 每种列表字段再使用其下的子目录, 便于区分不同用途的字典
     */
    private final File dictionariesRoot;

    /**
     * 各字典字段的计数器(标签 + 编辑框), 用于整体加载后刷新计数
     */
    private final List<CountPair> counters = new ArrayList<>();

    /**
     * 各字典字段的"配置默认内容"备份(编辑框 -> 加载自 config 的值),
     * 用于下拉切回 default 占位项时恢复
     */
    private final Map<JTextArea, String> defaultDictTexts = new HashMap<>();

    public BaseSettingTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, YamlReader yamlReader) {
        this.yamlReader = yamlReader;
        this.dictionariesRoot = resolveDictionariesDir();
        this.dictionariesRoot.mkdirs();

        JPanel root = new JPanel(new BorderLayout());

        // 二级子标签页: 每类配置一个独立子页, 避免单页内容过多
        JTabbedPane contentTabs = new JTabbedPane();
        contentTabs.addTab("基础配置", this.wrapTab(this.buildBasicContent()));
        contentTabs.addTab("域名扫描规则", this.wrapTab(this.buildDomainContent()));
        contentTabs.addTab("URL后缀黑名单", this.wrapTab(this.buildUrlSuffixContent()));
        contentTabs.addTab("Shiro Key爆破", this.wrapTab(this.buildCipherKeyContent()));
        root.add(contentTabs, BorderLayout.CENTER);

        // ---------- 底部操作栏 ----------
        JPanel operationBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        operationBar.add(this.buildButton("保存配置", e -> this.saveConfig()));
        operationBar.add(this.buildButton("重新加载", e -> this.loadConfig()));

        this.statusLabel = new JLabel("配置已加载", SwingConstants.RIGHT);
        this.statusLabel.setForeground(new Color(0, 120, 0));
        operationBar.add(this.statusLabel);

        root.add(operationBar, BorderLayout.SOUTH);

        tabs.addTab("基本设置", root);

        // 初始化时从配置填充表单
        this.loadConfig();
    }

    // ------------------------------------------------------------------
    // 各子页内容构建
    // ------------------------------------------------------------------

    private JPanel buildBasicContent() {
        JPanel rows = this.newRowContainer();
        this.addComboRow(rows, "messageLevel", "消息等级", new String[]{"PIVOTAL", "ALL"});
        this.addCheckboxRow(rows, "debug.showInUi", "调试信息显示到扫描队列UI");
        this.addIntRow(rows, "scan.siteScanNumber", "站点扫描次数(0=无限)");
        this.addIntRow(rows, "application.shiroFingerprintExtension.config.issueNumber", "单站点指纹问题上报上限(0=不限)");
        return rows;
    }

    private JPanel buildDomainContent() {
        JPanel rows = this.newRowContainer();
        this.addDictionaryList(rows, "scan.domainName.blacklist", "域名黑名单(每行一个, 支持 *.domain.com)", "domain-blacklist");
        this.addDictionaryList(rows, "scan.domainName.whitelist", "域名白名单(每行一个, 支持 *.domain.com)", "domain-whitelist");
        return rows;
    }

    private JPanel buildUrlSuffixContent() {
        JPanel rows = this.newRowContainer();
        this.addCheckboxRow(rows, "urlBlackListSuffix.config.isStart", "启用URL后缀过滤");
        this.addDictionaryList(rows, "urlBlackListSuffix.suffixList", "URL后缀黑名单(每行一个)", "url-suffix");
        return rows;
    }

    private JPanel buildCipherKeyContent() {
        JPanel rows = this.newRowContainer();
        this.addCheckboxRow(rows, "application.shiroCipherKeyExtension.config.isStart", "启用Key爆破");
        this.addCheckboxRow(rows, "application.shiroCipherKeyExtension.config.isScanCbcEncrypt", "扫描CBC加密");
        this.addCheckboxRow(rows, "application.shiroCipherKeyExtension.config.isScanGcmEncrypt", "扫描GCM加密");
        this.addIntRow(rows, "application.shiroCipherKeyExtension.config.issueNumber", "Key问题上限(0=不限)");
        this.addIntRow(rows, "application.shiroCipherKeyExtension.config.threadTotal", "线程数");
        this.addDoubleRow(rows, "application.shiroCipherKeyExtension.config.similarityRatio", "相似度阈值(0~1)");
        this.addDictionaryList(rows, "application.shiroCipherKeyExtension.config.payloads", "Shiro Key字典(可从下方字典加载, 也可直接编辑; 保存后写入config.yml)", "keys");
        return rows;
    }

    // ------------------------------------------------------------------
    // 操作
    // ------------------------------------------------------------------

    /**
     * 将表单值写入内存并落盘到 config.yml
     */
    private void saveConfig() {
        try {
            for (ConfigField field : this.fields) {
                this.yamlReader.setValueByKey(field.key, field.getValue());
            }

            if (this.yamlReader.save()) {
                this.setStatus(true, "保存成功: " + this.yamlReader.getConfigFilePath());
            } else {
                this.setStatus(false, "保存失败, 请查看Extender->Errors");
            }
        } catch (NumberFormatException e) {
            this.setStatus(false, "保存失败, 存在非法的数字输入: " + e.getMessage());
        } catch (Exception e) {
            this.setStatus(false, "保存失败: " + e.getMessage());
        }
    }

    /**
     * 从配置重新填充表单
     */
    private void loadConfig() {
        for (ConfigField field : this.fields) {
            try {
                field.load();
                // 记录每个字典字段从配置加载的默认内容, 供下拉切回 default 时恢复
                if (field instanceof ListField) {
                    this.defaultDictTexts.put(((ListField) field).area, ((ListField) field).area.getText());
                }
            } catch (Exception e) {
                // 单个字段读取失败(如配置项缺失/类型不符)不影响整体表单加载, 保证插件能正常启动
                this.setStatus(false, "部分配置加载失败: " + e.getMessage());
            }
        }
        this.setStatus(true, "配置已加载");
        this.refreshAllCounters();
    }

    /**
     * 更新底部状态栏文案与颜色
     */
    private void setStatus(boolean success, String msg) {
        if (this.statusLabel == null) {
            return;
        }
        this.statusLabel.setText(msg);
        this.statusLabel.setForeground(success ? new Color(0, 120, 0) : new Color(200, 0, 0));
    }

    // ------------------------------------------------------------------
    // 字典相关
    // ------------------------------------------------------------------

    /**
     * 定位字典目录: 与 config.yml 同级目录下的 dictionaries 文件夹
     */
    private File resolveDictionariesDir() {
        File configFile = new File(this.yamlReader.getConfigFilePath());
        File parent = configFile.getParentFile();
        if (parent != null) {
            return new File(parent, "dictionaries");
        }
        return new File("dictionaries");
    }

    // ------------------------------------------------------------------
    // 表单构建辅助 (基于每行独立面板, 避免 GridBagLayout 布局重叠)
    // ------------------------------------------------------------------

    private JPanel newRowContainer() {
        JPanel rows = new JPanel();
        rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));
        return rows;
    }

    /**
     * 将子页内容包一层滚动视图, 作为二级标签页的组件
     */
    private JComponent wrapTab(Component inner) {
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        wrap.add(new JScrollPane(inner), BorderLayout.CENTER);
        return wrap;
    }

    private JButton buildButton(String text, java.awt.event.ActionListener listener) {
        JButton button = new JButton(text);
        button.addActionListener(listener);
        return button;
    }

    /**
     * 让行横向铺满容器并左对齐
     */
    private void fullWidthRow(JComponent row) {
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
    }

    /**
     * 向 rows 加入一个"标签 + 编辑器"的行
     */
    private void addEditorRow(JPanel rows, String label, JComponent editor) {
        JPanel row = new JPanel(new BorderLayout(10, 2));
        row.add(new JLabel(label), BorderLayout.WEST);
        row.add(editor, BorderLayout.CENTER);
        this.fullWidthRow(row);
        rows.add(row);
        rows.add(Box.createVerticalStrut(2));
    }

    /**
     * 向 rows 加入一个复选框行
     */
    private JCheckBox addCheckboxRow(JPanel rows, String key, String label) {
        JCheckBox box = new JCheckBox(label);
        this.fields.add(new BoolField(key, box));
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row.add(box);
        this.fullWidthRow(row);
        rows.add(row);
        rows.add(Box.createVerticalStrut(2));
        return box;
    }

    private void addComboRow(JPanel rows, String key, String label, String[] values) {
        JComboBox<String> combo = new JComboBox<>(values);
        this.fields.add(new ComboField(key, combo));
        this.addEditorRow(rows, label, combo);
    }

    private void addIntRow(JPanel rows, String key, String label) {
        JTextField field = new JTextField(10);
        this.fields.add(new IntField(key, field));
        this.addEditorRow(rows, label, field);
    }

    private void addDoubleRow(JPanel rows, String key, String label) {
        JTextField field = new JTextField(10);
        this.fields.add(new DoubleField(key, field));
        this.addEditorRow(rows, label, field);
    }

    /**
     * 通用"字典字段": 每个列表字段都带独立的字典下拉 + 导入/刷新/清空 + 计数
     *
     * @param dictDirName 字典子目录名, 用于区分不同用途的字典
     */
    private void addDictionaryList(JPanel rows, String key, String label, String dictDirName) {
        JTextArea area = new JTextArea(4, 46);
        area.setLineWrap(false);
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        this.fields.add(new ListField(key, area));

        final File dictDir = new File(this.dictionariesRoot, dictDirName);
        final String placeholder = "default";

        // 顶部工具栏: 字典下拉 + 操作按钮 + 计数
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));

        JComboBox<String> box = new JComboBox<>();
        box.setToolTipText("字典目录: " + dictDir.getAbsolutePath());
        // 不设置 prototype, 让下拉框宽度按最长文件名自适应, 避免长名称被截断

        JLabel countLabel = new JLabel("0");
        countLabel.setForeground(new Color(0, 100, 200));

        JButton refreshBtn = this.buildButton("刷新列表", e -> this.refreshDictionaryBox(box, dictDir, placeholder));
        JButton importBtn = this.buildButton("导入字典...", e -> this.importDictionaryTo(box, dictDir, placeholder));
        JButton clearBtn = this.buildButton("清空", e -> {
            area.setText("");
            this.updateCounter(countLabel, area);
        });

        toolbar.add(new JLabel("字典:"));
        toolbar.add(box);
        toolbar.add(refreshBtn);
        toolbar.add(importBtn);
        toolbar.add(clearBtn);

        // 触发器: 下拉切换时装载字典内容 (用 ItemListener, 选中/切换均可靠触发)
        box.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                this.loadDictionaryInto(box, dictDir, countLabel, area, placeholder);
            }
        });

        this.counters.add(new CountPair(countLabel, area));

        // 编辑框内容任何变化(切字典/导入/清空/手动输入)都自动刷新计数, 避免计数与实际条目不一致
        area.getDocument().addDocumentListener(new SimpleDocumentListener(() -> this.updateCounter(countLabel, area)));

        JPanel control = new JPanel(new BorderLayout(4, 4));
        control.add(toolbar, BorderLayout.NORTH);
        control.add(new JScrollPane(area), BorderLayout.CENTER);

        this.addEditorRow(rows, label, control);

        // 初始扫描一次当前字典子目录
        this.refreshDictionaryBox(box, dictDir, placeholder);
    }

    /**
     * 刷新字典下拉列表: 顶部固定一个用途占位项, 下面列出真实字典文件
     */
    private void refreshDictionaryBox(JComboBox<String> box, File dictDir, String placeholder) {
        String old = box.getSelectedItem() == null ? null : (String) box.getSelectedItem();

        box.removeAllItems();
        box.addItem(placeholder);
        List<String> names = DictionaryManager.list(dictDir);
        for (String name : names) {
            box.addItem(name);
        }
        box.setEnabled(true);

        // 若之前选中的是真实字典且仍存在, 则保留选择; 否则回到占位项
        if (old != null && !old.equals(placeholder)) {
            for (int i = 1; i < box.getItemCount(); i++) {
                if (box.getItemAt(i).equals(old)) {
                    box.setSelectedIndex(i);
                    return;
                }
            }
        }
        box.setSelectedIndex(0);
    }

    /**
     * 从本地文件导入字典到指定子目录
     */
    private void importDictionaryTo(JComboBox<String> box, File dictDir, String placeholder) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("选择要导入的字典文件");
        chooser.setFileFilter(new FileNameExtensionFilter("字典文件 (*.txt;*.dic)", "txt", "dic"));
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File source = chooser.getSelectedFile();
        String name = source.getName();
        if (DictionaryManager.importDictionary(dictDir, name, source)) {
            this.setStatus(true, "字典导入成功: " + name);
            this.refreshDictionaryBox(box, dictDir, placeholder);
            for (int i = 1; i < box.getItemCount(); i++) {
                if (box.getItemAt(i).equals(name)) {
                    box.setSelectedIndex(i);
                    break;
                }
            }
        } else {
            this.setStatus(false, "字典导入失败");
        }
    }

    /**
     * 字典下拉切换时, 把选中字典内容装载到编辑框 (default 占位项则恢复配置默认内容)
     */
    private void loadDictionaryInto(JComboBox<String> box, File dictDir, JLabel countLabel, JTextArea area, String placeholder) {
        Object sel = box.getSelectedItem();
        if (sel == null) {
            return;
        }
        // 切回 default 占位项: 恢复该字段从配置加载的默认内容
        if (sel.equals(placeholder)) {
            area.setText(this.defaultDictTexts.getOrDefault(area, ""));
            this.updateCounter(countLabel, area);
            this.setStatus(true, "已切回默认配置");
            return;
        }
        List<String> loaded = DictionaryManager.load(dictDir, (String) sel);
        StringBuilder sb = new StringBuilder();
        for (String line : loaded) {
            sb.append(line).append(System.lineSeparator());
        }
        area.setText(sb.toString());
        this.updateCounter(countLabel, area);
        this.setStatus(true, "已载入字典[" + sel + "], 共 " + loaded.size() + " 条");
    }

    private void updateCounter(JLabel countLabel, JTextArea area) {
        if (countLabel == null) {
            return;
        }
        int count = 0;
        String text = area.getText();
        if (text != null && !text.isEmpty()) {
            count = new StringTokenizer(text, System.lineSeparator() + "\r\n").countTokens();
        }
        countLabel.setText(count + " items");
    }

    /**
     * 整体加载后刷新所有字典字段的计数
     */
    private void refreshAllCounters() {
        for (CountPair pair : this.counters) {
            this.updateCounter(pair.label, pair.area);
        }
    }

    // ------------------------------------------------------------------
    // 结构化配置字段抽象
    // ------------------------------------------------------------------

    private abstract class ConfigField {
        protected final String key;

        protected ConfigField(String key) {
            this.key = key;
        }

        /**
         * 从配置读取并填充控件
         */
        abstract void load();

        /**
         * 取回控件里的值, 供保存使用
         */
        abstract Object getValue();
    }

    private class BoolField extends ConfigField {
        private final JCheckBox box;

        private BoolField(String key, JCheckBox box) {
            super(key);
            this.box = box;
        }

        @Override
        void load() {
            Object value = yamlReader.getValueByKey(this.key);
            // 配置项缺失或非法时返回 null, 这里统一降级为 false, 避免空指针导致插件无法启动
            this.box.setSelected(Boolean.TRUE.equals(value));
        }

        @Override
        Object getValue() {
            return this.box.isSelected();
        }
    }

    private class ComboField extends ConfigField {
        private final JComboBox<String> combo;

        private ComboField(String key, JComboBox<String> combo) {
            super(key);
            this.combo = combo;
        }

        @Override
        void load() {
            String current = yamlReader.getString(this.key);
            for (int i = 0; i < this.combo.getItemCount(); i++) {
                if (this.combo.getItemAt(i).equals(current)) {
                    this.combo.setSelectedIndex(i);
                    return;
                }
            }
            if (this.combo.getItemCount() > 0) {
                this.combo.setSelectedIndex(0);
            }
        }

        @Override
        Object getValue() {
            return this.combo.getSelectedItem();
        }
    }

    private class IntField extends ConfigField {
        private final JTextField field;

        private IntField(String key, JTextField field) {
            super(key);
            this.field = field;
        }

        @Override
        void load() {
            Object value = yamlReader.getValueByKey(this.key);
            this.field.setText(value == null ? "" : String.valueOf(value));
        }

        @Override
        Object getValue() {
            String text = this.field.getText() == null ? "" : this.field.getText().trim();
            if (text.isEmpty()) {
                return 0;
            }
            return Integer.parseInt(text);
        }
    }

    private class DoubleField extends ConfigField {
        private final JTextField field;

        private DoubleField(String key, JTextField field) {
            super(key);
            this.field = field;
        }

        @Override
        void load() {
            Object value = yamlReader.getValueByKey(this.key);
            this.field.setText(value == null ? "" : String.valueOf(value));
        }

        @Override
        Object getValue() {
            String text = this.field.getText() == null ? "" : this.field.getText().trim();
            if (text.isEmpty()) {
                return 0.0;
            }
            return Double.parseDouble(text);
        }
    }

    private class ListField extends ConfigField {
        private final JTextArea area;

        private ListField(String key, JTextArea area) {
            super(key);
            this.area = area;
        }

        @Override
        void load() {
            List<String> list = yamlReader.getStringList(this.key);
            StringBuilder sb = new StringBuilder();
            if (list != null) {
                for (String item : list) {
                    sb.append(item).append(System.lineSeparator());
                }
            }
            this.area.setText(sb.toString());
        }

        @Override
        Object getValue() {
            List<String> list = new ArrayList<>();
            StringTokenizer tokenizer = new StringTokenizer(
                    this.area.getText() == null ? "" : this.area.getText(), System.lineSeparator() + "\r\n");
            while (tokenizer.hasMoreTokens()) {
                String item = tokenizer.nextToken().trim();
                if (!item.isEmpty()) {
                    list.add(item);
                }
            }
            return list;
        }
    }

    // ------------------------------------------------------------------
    // 字典字段计数器 / 字典管理工具
    // ------------------------------------------------------------------

    /**
     * 记录每个字典字段的"计数标签 + 编辑框", 用于整体加载后统一刷新计数
     */
    private static class CountPair {
        final JLabel label;
        final JTextArea area;

        CountPair(JLabel label, JTextArea area) {
            this.label = label;
            this.area = area;
        }
    }

    /**
     * 简化版 DocumentListener, 文本任意变化时只执行一个动作
     */
    private static class SimpleDocumentListener implements javax.swing.event.DocumentListener {
        private final Runnable action;

        SimpleDocumentListener(Runnable action) {
            this.action = action;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            this.action.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            this.action.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            this.action.run();
        }
    }

    private static class DictionaryManager {
        static List<String> list(File dir) {
            List<String> names = new ArrayList<>();
            if (dir == null || !dir.exists() || !dir.isDirectory()) {
                return names;
            }
            File[] files = dir.listFiles((d, name) -> name.toLowerCase().endsWith(".txt")
                    || name.toLowerCase().endsWith(".dic"));
            if (files != null) {
                java.util.Arrays.sort(files, Comparator.comparing(File::getName));
                for (File f : files) {
                    names.add(f.getName());
                }
            }
            return names;
        }

        static List<String> load(File dir, String name) {
            List<String> lines = new ArrayList<>();
            File file = new File(dir, name);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) {
                        lines.add(trimmed);
                    }
                }
            } catch (IOException e) {
                // 忽略单个字典读取失败
            }
            return lines;
        }

        static boolean importDictionary(File dir, String name, File source) {
            if (dir != null && !dir.exists()) {
                dir.mkdirs();
            }
            File dest = new File(dir, name);
            try {
                Files.copy(source.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }
}