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
            "1. Right-click any HTTP request in Burp (Proxy, Repeater, Target, etc.)\n" +
            "2. Select \"Send to BypassFuzzer\"\n" +
            "3. A new tab will open for that request\n" +
            "4. Select which attack types to run (or use Check All)\n" +
            "5. Configure options: Collaborator payloads, rate limiting, auto-throttle\n" +
            "6. Click \"Start Fuzzing\"\n" +
            "7. Review results in real-time with dynamic filtering\n\n" +
            "8 Attack Types Available:\n" +
            "• Header - 283+ bypass headers (X-Forwarded-For, X-Original-URL, etc.)\n" +
            "• Path - 367+ URL/path manipulations (../, .;/, %2e, etc.)\n" +
            "• Verb - 11 HTTP methods + method override techniques\n" +
            "• Debug Params - 31+ debug parameters with case variations\n" +
            "• Trailing Dot - Absolute domain bypass (example.com.)\n" +
            "• Trailing Slash - Tests with/without trailing slash\n" +
            "• Protocol - HTTP/1.0 and HTTP/0.9 downgrades\n" +
            "• Case Variation - Random capitalizations with smart limits\n\n" +
            "Features:\n" +
            "• Smart filtering to reduce noise and highlight interesting responses\n" +
            "• Rate limiting with configurable requests/second (default: unlimited)\n" +
            "• Auto-throttle: automatically slows down when 429/503 detected\n" +
            "• Dynamic Burp Collaborator payload generation (Pro only)\n" +
            "• Color-code results for easy identification\n" +
            "• Send findings directly to Repeater or Intruder\n" +
            "• Multiple concurrent fuzzing sessions (each in its own tab)\n\n" +
            "Tips:\n" +
            "• Set requests/second to 5-10 to avoid overwhelming targets\n" +
            "• Auto-throttle will reduce speed if rate limiting is detected\n" +
            "• Path and Trailing Slash attacks are skipped on root paths (/)\n" +
            "• Use filters to show only specific status codes or content types\n" +
            "• Right-click results to colorize interesting findings"
        );
        instructions.setEditable(false);
        instructions.setBackground(panel.getBackground());
        instructions.setFont(new Font("Arial", Font.PLAIN, 13));
        instructions.setAlignmentX(Component.CENTER_ALIGNMENT);
        instructions.setMaximumSize(new Dimension(700, 500));

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
