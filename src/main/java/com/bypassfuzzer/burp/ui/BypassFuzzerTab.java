package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.session.FuzzingSessionController;
import com.bypassfuzzer.burp.session.SessionRegistry;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.ui.session.CoverageSweepPanel;
import com.bypassfuzzer.burp.ui.dashboard.ActivityRegistry;
import com.bypassfuzzer.burp.ui.dashboard.DashboardPanel;
import com.bypassfuzzer.burp.update.VersionCheckResult;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.EnumMap;
import java.util.Map;

/**
 * Main UI tab for the BypassFuzzer extension.
 * Uses a tabbed interface to manage multiple fuzzing sessions.
 */
public class BypassFuzzerTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane tabbedPane;
    private final SessionRegistry sessionRegistry;
    private final JPanel updateBannerHost;
    private final Map<TargetedMode, JTabbedPane> modeSessionTabs;
    private final GlobalTrafficGovernor globalGovernor;
    private final ActivityRegistry activityRegistry;
    private DashboardPanel dashboardPanel;
    private CoverageSweepPanel sweepPanel;

    public BypassFuzzerTab(MontoyaApi api) {
        this.api = api;
        this.tabbedPane = new JTabbedPane();
        this.globalGovernor = new GlobalTrafficGovernor();
        this.activityRegistry = new ActivityRegistry();
        this.sessionRegistry = new SessionRegistry(api, globalGovernor);
        this.updateBannerHost = new JPanel(new BorderLayout());
        this.modeSessionTabs = new EnumMap<>(TargetedMode.class);
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        dashboardPanel = new DashboardPanel(api, globalGovernor, activityRegistry);
        tabbedPane.addTab("Dashboard", dashboardPanel);
        sweepPanel = new CoverageSweepPanel(api, globalGovernor);
        tabbedPane.addTab("Sweep", sweepPanel);
        activityRegistry.register(sweepPanel, () -> tabbedPane.setSelectedComponent(sweepPanel));
        dashboardPanel.refresh();
        for (TargetedMode mode : TargetedMode.values()) {
            JTabbedPane sessionTabs = new JTabbedPane();
            modeSessionTabs.put(mode, sessionTabs);
            tabbedPane.addTab(mode.title(), sessionTabs);
        }

        updateBannerHost.setVisible(false);
        add(updateBannerHost, BorderLayout.NORTH);
        add(tabbedPane, BorderLayout.CENTER);
    }

    public void showUpdateBanner(VersionCheckResult result) {
        Runnable updateUi = () -> {
            updateBannerHost.removeAll();
            updateBannerHost.add(createUpdateBanner(result), BorderLayout.CENTER);
            updateBannerHost.setVisible(true);
            revalidate();
            repaint();
        };

        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    private JPanel createUpdateBanner(VersionCheckResult result) {
        JPanel banner = new JPanel(new BorderLayout(12, 0));
        banner.setName("updateBanner");
        banner.setBackground(new Color(255, 244, 214));
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(214, 173, 82)),
            BorderFactory.createEmptyBorder(10, 14, 10, 12)
        ));

        JLabel message = new JLabel(updateBannerMessage(result));
        message.setName("updateBannerMessage");
        message.setForeground(new Color(45, 33, 12));

        JButton dismissButton = new JButton("Dismiss");
        dismissButton.setName("updateBannerDismiss");
        dismissButton.setFocusable(false);
        dismissButton.addActionListener(event -> {
            banner.setVisible(false);
            updateBannerHost.setVisible(false);
            updateBannerHost.removeAll();
            revalidate();
            repaint();
        });

        banner.add(message, BorderLayout.CENTER);
        banner.add(dismissButton, BorderLayout.EAST);
        return banner;
    }

    static String updateBannerMessage(VersionCheckResult result) {
        return "BypassFuzzer " + result.latestVersion()
            + " is available. You are running " + result.currentVersion()
            + ". Download the latest bypassfuzzer.jar from GitHub releases.";
    }

    /**
     * Load a request into a new Bypass session tab.
     *
     * @param request The HTTP request to fuzz
     */
    public void loadRequest(HttpRequest request) {
        loadRequest(request, TargetedMode.BYPASS);
    }

    /**
     * Load a request into a new session tab under the selected targeted mode.
     *
     * @param request The HTTP request to fuzz
     * @param mode The destination mode
     */
    public void loadRequest(HttpRequest request, TargetedMode mode) {
        loadRequest(request, null, mode);
    }

    public void loadRequest(HttpRequestResponse exchange, TargetedMode mode) {
        loadRequest(exchange.request(), exchange.response(), mode);
    }

    private void loadRequest(HttpRequest request, HttpResponse response, TargetedMode mode) {
        FuzzingSessionController sessionController = sessionRegistry.createSession(request);
        FuzzingSessionTab sessionTab = new FuzzingSessionTab(api, sessionController, mode, response);
        JTabbedPane sessionTabs = modeSessionTabs.get(mode);

        int tabIndex = sessionTabs.getTabCount();
        sessionTabs.addTab(sessionTab.getTabTitle(), sessionTab);
        sessionTabs.setTabComponentAt(
            tabIndex,
            createSessionTabComponent(sessionTab.getTabTitle(), sessionTabs, sessionTab)
        );

        sessionTabs.setSelectedIndex(tabIndex);
        tabbedPane.setSelectedComponent(sessionTabs);
        activityRegistry.register(sessionTab, () -> {
            tabbedPane.setSelectedComponent(sessionTabs);
            sessionTabs.setSelectedComponent(sessionTab);
        });
        dashboardPanel.refresh();

        api.logging().logToOutput("New " + mode.title() + " session created: " + request.url());
    }

    /**
     * Stop all running fuzzing sessions.
     * Called when extension is unloaded.
     */
    public void cleanup() {
        try {
            api.logging().logToOutput("BypassFuzzer cleanup: stopping all sessions...");
        } catch (Exception e) {
            // API may be unavailable during unload
        }

        for (JTabbedPane sessionTabs : modeSessionTabs.values()) {
            for (int index = 0; index < sessionTabs.getTabCount(); index++) {
                Component component = sessionTabs.getComponentAt(index);
                if (component instanceof FuzzingSessionTab sessionTab) {
                    sessionTab.cleanup();
                }
            }
        }
        if (sweepPanel != null) {
            sweepPanel.cleanup();
        }
        if (dashboardPanel != null) {
            dashboardPanel.cleanup();
        }

        sessionRegistry.closeAllSessions();

        try {
            api.logging().logToOutput("BypassFuzzer cleanup completed");
        } catch (Exception e) {
            // API may be unavailable during unload
        }
    }

    /** Create the shared, renameable session header used by every targeted mode. */
    private JPanel createSessionTabComponent(String title, JTabbedPane sessionTabs, FuzzingSessionTab sessionTab) {
        JPanel tabPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabPanel.setOpaque(false);

        JLabel tabLabel = new JLabel(title);
        tabLabel.setToolTipText("Double-click or right-click to rename this tab");
        Runnable rename = () -> renameSessionTab(sessionTabs, tabPanel, tabLabel);
        JPopupMenu tabMenu = new JPopupMenu();
        JMenuItem renameItem = new JMenuItem("Rename tab...");
        renameItem.addActionListener(e -> rename.run());
        tabMenu.add(renameItem);
        tabLabel.setComponentPopupMenu(tabMenu);
        tabPanel.setComponentPopupMenu(tabMenu);
        Runnable select = () -> {
            int currentIndex = sessionTabs.indexOfTabComponent(tabPanel);
            if (currentIndex != -1) sessionTabs.setSelectedIndex(currentIndex);
        };
        MouseAdapter tabClicks = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (!SwingUtilities.isLeftMouseButton(event)) return;
                select.run();
                if (event.getClickCount() == 2) rename.run();
            }

            @Override
            public void mousePressed(MouseEvent event) {
                if (event.isPopupTrigger()) select.run();
            }

            @Override
            public void mouseReleased(MouseEvent event) {
                if (event.isPopupTrigger()) select.run();
            }
        };
        tabLabel.addMouseListener(tabClicks);
        tabPanel.addMouseListener(tabClicks);
        tabPanel.add(tabLabel);

        JButton closeButton = new JButton("×");
        closeButton.setPreferredSize(new Dimension(17, 17));
        closeButton.setMargin(new Insets(0, 0, 0, 0));
        closeButton.setFont(new Font("Arial", Font.BOLD, 12));
        closeButton.setFocusable(false);
        closeButton.setBorderPainted(false);
        closeButton.setContentAreaFilled(false);

        closeButton.addActionListener(e -> {
            int currentIndex = sessionTabs.indexOfTabComponent(tabPanel);
            if (currentIndex != -1) {
                int confirm = JOptionPane.showConfirmDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Close this fuzzing session?",
                    "Confirm Close",
                    JOptionPane.YES_NO_OPTION
                );
                if (confirm == JOptionPane.YES_OPTION) {
                    sessionTab.cleanup();
                    sessionRegistry.closeSession(sessionTab.getSessionId());
                    activityRegistry.unregister(sessionTab.activityId());
                    sessionTabs.removeTabAt(currentIndex);
                    dashboardPanel.refresh();
                }
            }
        });

        tabPanel.add(closeButton);

        return tabPanel;
    }

    private void renameSessionTab(JTabbedPane sessionTabs, JPanel tabPanel, JLabel tabLabel) {
        int currentIndex = sessionTabs.indexOfTabComponent(tabPanel);
        if (currentIndex == -1) {
            return;
        }

        String name = JOptionPane.showInputDialog(
            api.userInterface().swingUtils().suiteFrame(),
            "Tab name:",
            tabLabel.getText()
        );
        if (name == null || name.isBlank()) {
            return;
        }

        String newTitle = name.trim();
        sessionTabs.setTitleAt(currentIndex, newTitle);
        tabLabel.setText(newTitle);
    }
}
