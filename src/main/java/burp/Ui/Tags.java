package burp.Ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JToggleButton;

import burp.ITab;
import burp.IBurpExtenderCallbacks;

import burp.Bootstrap.YamlReader;
import burp.Bootstrap.GlobalVariableReader;

public class Tags implements ITab {
    private final JTabbedPane tabs;

    private final JPanel rootPanel;

    private final String tagName;

    private BaseSettingTag baseSettingTag;
    private ScanQueueTag scanQueueTag;

    private final GlobalVariableReader globalVariableReader;

    // 顶部常驻的「启动/关闭」启停开关
    private final JToggleButton startStopToggle;

    // 状态文本: ● 扫描已启用 / ● 扫描已关闭
    private final JLabel scanState;

    public Tags(IBurpExtenderCallbacks callbacks, String name, GlobalVariableReader globalVariableReader) {
        this.tagName = name;
        this.globalVariableReader = globalVariableReader;

        tabs = new JTabbedPane();

        YamlReader yamlReader = YamlReader.getInstance(callbacks);

        // 扫描队列-窗口
        ScanQueueTag scanQueueTag = new ScanQueueTag(callbacks, tabs);
        this.scanQueueTag = scanQueueTag;

        // 基本设置-窗口
        BaseSettingTag baseSettingTag = new BaseSettingTag(callbacks, tabs, yamlReader);
        this.baseSettingTag = baseSettingTag;

        // 顶部常驻启停开关(样式参照 BurpFastjsonScan: 选中=已启用显示"关闭", 未选中显示"启动")
        this.startStopToggle = new JToggleButton();
        this.scanState = new JLabel();
        this.refreshToggleState();

        // 热插拔: 关闭即中止(含在跑的key爆破), 开启即恢复扫描
        // 复用 isExtensionUnload 标志, key爆破线程每个key前都会检查它
        this.startStopToggle.addActionListener(e -> {
            boolean on = this.startStopToggle.isSelected();
            this.refreshToggleState();
            if (this.globalVariableReader != null) {
                // 关闭则停止(含在跑的key爆破), 开启则恢复扫描
                this.globalVariableReader.putBooleanData("isExtensionUnload", !on);
                // 开关状态每次变化(关闭或重新开启)都清零各站点扫描计数,
                // 保证"关闭再打开"后站点能再被按 siteScanNumber 扫描一次
                this.globalVariableReader.resetSiteScan();
            }
        });

        // 顶部工具条: 左标题+状态, 右启停开关(参照 BurpFastjsonScan 的扫描栏样式)
        JLabel title = new JLabel(this.tagName);
        title.setFont(title.getFont().deriveFont(Font.BOLD, title.getFont().getSize2D() + 2f));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        left.add(title);
        left.add(this.scanState);
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.add(this.startStopToggle);

        JPanel topBar = new JPanel(new BorderLayout(0, 0));
        topBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, topBar.getBackground().darker()),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        topBar.add(left, BorderLayout.WEST);
        topBar.add(right, BorderLayout.EAST);

        JPanel root = new JPanel(new BorderLayout());
        root.add(topBar, BorderLayout.NORTH);
        root.add(tabs, BorderLayout.CENTER);
        this.rootPanel = root;

        // 自定义组件-导入
        callbacks.customizeUiComponent(root);

        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(Tags.this);

        // 初始化开关状态(触发监听器, 同步 isExtensionUnload 与站点计数)
        Boolean configStart = yamlReader.getBoolean("isStart");
        this.startStopToggle.setSelected(configStart == null || configStart);
        this.refreshToggleState();
    }

    /**
     * 根据开关状态刷新按钮与状态文本
     */
    private void refreshToggleState() {
        boolean on = this.startStopToggle.isSelected();
        this.startStopToggle.setText(on ? "关闭" : "启动");
        this.scanState.setText(on ? "● 扫描已启用" : "● 扫描已关闭");
        this.scanState.setForeground(on ? new Color(0x1B8A2C) : new Color(0xB00020));
    }

    /**
     * 插件是否处于启动状态
     *
     * @return
     */
    public Boolean isStart() {
        return this.startStopToggle.isSelected();
    }

    /**
     * 基础设置tag
     *
     * @return
     */
    public BaseSettingTag getBaseSettingTagClass() {
        return this.baseSettingTag;
    }

    /**
     * 扫描队列tag
     * 可通过该类提供的方法,进行tag任务的添加与修改
     *
     * @return
     */
    public ScanQueueTag getScanQueueTagClass() {
        return this.scanQueueTag;
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.rootPanel;
    }
}
