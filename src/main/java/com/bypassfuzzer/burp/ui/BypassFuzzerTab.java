package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Main UI tab for the BypassFuzzer extension.
 * Uses a tabbed interface to manage multiple fuzzing sessions.
 */
public class BypassFuzzerTab extends JPanel {

    private final MontoyaApi api;
    private final JTabbedPane tabbedPane;
    private final List<FuzzingSessionTab> sessionTabs;
    private int sessionCounter = 1;

    public BypassFuzzerTab(MontoyaApi api) {
        this.api = api;
        this.tabbedPane = new JTabbedPane();
        this.sessionTabs = new ArrayList<>();
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        // Welcome tab
        JPanel welcomePanel = createWelcomePanel();
        tabbedPane.addTab("Welcome", welcomePanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createWelcomePanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(50, 50, 50, 50));

        JLabel titleLabel = new JLabel("BypassFuzzer for Burp Suite");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel subtitleLabel = new JLabel("Access Control Bypass Testing Tool");
        subtitleLabel.setFont(new Font("Arial", Font.PLAIN, 16));
        subtitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JTextArea instructions = new JTextArea();
        instructions.setText(
            "Getting Started:\n\n" +
            "1. Right-click any HTTP request in Burp (Proxy, Repeater, etc.)\n" +
            "2. Select \"Send to BypassFuzzer\"\n" +
            "3. A new tab will open for that request\n" +
            "4. Select which attack types to run\n" +
            "5. Click \"Start Fuzzing\"\n\n" +
            "Attack Types:\n" +
            "• Header - 282+ bypass headers (X-Forwarded-For, X-Original-URL, etc.)\n" +
            "• Path - 367+ URL/path manipulations (../, .;/, %2e, etc.)\n" +
            "• Verb - HTTP methods + method override techniques\n" +
            "• Trailing Dot - Absolute domain bypass (example.com.)\n" +
            "• Protocol - HTTP/1.0 and HTTP/0.9 downgrades\n\n" +
            "Each request gets its own tab so you can fuzz multiple targets simultaneously."
        );
        instructions.setEditable(false);
        instructions.setBackground(panel.getBackground());
        instructions.setFont(new Font("Arial", Font.PLAIN, 14));
        instructions.setAlignmentX(Component.CENTER_ALIGNMENT);
        instructions.setMaximumSize(new Dimension(600, 400));

        centerPanel.add(titleLabel);
        centerPanel.add(Box.createVerticalStrut(10));
        centerPanel.add(subtitleLabel);
        centerPanel.add(Box.createVerticalStrut(30));
        centerPanel.add(instructions);

        panel.add(centerPanel, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Load a request into a new fuzzing session tab.
     */
    public void loadRequest(HttpRequest request) {
        // Create new session tab
        FuzzingSessionTab sessionTab = new FuzzingSessionTab(api, request);
        sessionTabs.add(sessionTab);

        // Add tab with close button
        int tabIndex = tabbedPane.getTabCount();
        tabbedPane.addTab(sessionTab.getTabTitle(), sessionTab);
        tabbedPane.setTabComponentAt(tabIndex, createTabComponent(sessionTab.getTabTitle(), tabIndex));

        // Switch to new tab
        tabbedPane.setSelectedIndex(tabIndex);

        api.logging().logToOutput("New fuzzing session created: " + request.url());
        sessionCounter++;
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

        for (FuzzingSessionTab sessionTab : sessionTabs) {
            try {
                sessionTab.cleanup();
            } catch (Exception e) {
                // Ignore errors during cleanup
            }
        }
        sessionTabs.clear();

        try {
            api.logging().logToOutput("BypassFuzzer cleanup completed");
        } catch (Exception e) {
            // API may be unavailable during unload
        }
    }

    /**
     * Create a tab component with a close button.
     */
    private JPanel createTabComponent(String title, int tabIndex) {
        JPanel tabPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        tabPanel.setOpaque(false);

        JLabel tabLabel = new JLabel(title);
        tabPanel.add(tabLabel);

        // Close button (only for non-welcome tabs)
        if (tabIndex > 0) {
            JButton closeButton = new JButton("×");
            closeButton.setPreferredSize(new Dimension(17, 17));
            closeButton.setMargin(new Insets(0, 0, 0, 0));
            closeButton.setFont(new Font("Arial", Font.BOLD, 12));
            closeButton.setFocusable(false);
            closeButton.setBorderPainted(false);
            closeButton.setContentAreaFilled(false);

            closeButton.addActionListener(e -> {
                int currentIndex = tabbedPane.indexOfTabComponent(tabPanel);
                if (currentIndex != -1) {
                    int confirm = JOptionPane.showConfirmDialog(
                        this,
                        "Close this fuzzing session?",
                        "Confirm Close",
                        JOptionPane.YES_NO_OPTION
                    );
                    if (confirm == JOptionPane.YES_OPTION) {
                        tabbedPane.removeTabAt(currentIndex);
                    }
                }
            });

            tabPanel.add(closeButton);
        }

        return tabPanel;
    }
}
