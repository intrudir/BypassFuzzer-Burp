package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.collaborator.CollaboratorSupport;
import com.bypassfuzzer.burp.http.RequestPathUtils;
import com.bypassfuzzer.burp.session.FuzzingSessionController;
import com.bypassfuzzer.burp.session.SessionPreflightAnalyzer;
import com.bypassfuzzer.burp.session.SessionRunOptions;
import com.bypassfuzzer.burp.session.SessionState;
import com.bypassfuzzer.burp.ui.session.AttackSelectionPanel;
import com.bypassfuzzer.burp.ui.session.IdorPanel;
import com.bypassfuzzer.burp.ui.session.RunOptionsPanel;
import com.bypassfuzzer.burp.ui.session.SessionResultsPanel;
import com.bypassfuzzer.burp.ui.session.SessionResultsWorkspace;
import com.bypassfuzzer.burp.ui.session.SessionRunOptionsSupport;
import com.bypassfuzzer.burp.ui.session.UrlValidationPanel;
import com.bypassfuzzer.burp.ui.dashboard.ActivitySnapshot;
import com.bypassfuzzer.burp.ui.dashboard.ActivityState;
import com.bypassfuzzer.burp.ui.dashboard.ManagedActivity;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;

/**
 * Individual fuzzing session tab.
 */
public class FuzzingSessionTab extends JPanel implements ManagedActivity {

    private final MontoyaApi api;
    private final FuzzingSessionController sessionController;
    private final FuzzerConfig config;
    private final HttpRequest request;
    private final String tabTitle;
    private final TargetedMode mode;
    private final SessionPreflightAnalyzer preflightAnalyzer = new SessionPreflightAnalyzer();

    private JButton startButton;
    private JButton stopButton;
    private JButton pauseButton;
    private JLabel statusLabel;
    private JLabel warningLabel;
    private AttackSelectionPanel attackSelectionPanel;
    private RunOptionsPanel runOptionsPanel;
    private JButton optionsButton;
    private JDialog optionsDialog;
    private SessionResultsWorkspace resultsWorkspace;
    private UrlValidationPanel urlValidationPanel;
    private IdorPanel idorPanel;

    private volatile boolean shuttingDown = false;

    public FuzzingSessionTab(MontoyaApi api, FuzzingSessionController sessionController) {
        this(api, sessionController, TargetedMode.BYPASS);
    }

    public FuzzingSessionTab(MontoyaApi api, FuzzingSessionController sessionController, TargetedMode mode) {
        this.api = api;
        this.sessionController = sessionController;
        this.request = sessionController.request();
        this.config = sessionController.config();
        this.mode = mode;
        this.tabTitle = request.method() + " " + truncate(RequestPathUtils.extractPath(request.url()), 30);

        if (mode == TargetedMode.BYPASS) {
            sessionController.addResultListener(this::addResult);
            sessionController.addStateListener(this::handleSessionStateChange);
        }

        initializeUi();
        if (mode == TargetedMode.BYPASS) {
            applyFilters();
        }
    }

    public String getTabTitle() {
        return tabTitle;
    }

    public String getSessionId() {
        return sessionController.sessionId();
    }

    @Override
    public String activityId() {
        return getSessionId();
    }

    @Override
    public ActivitySnapshot activitySnapshot() {
        if (mode == TargetedMode.IDOR) return idorPanel.activitySnapshot(activityId(), mode.title(), targetLabel());
        if (mode == TargetedMode.URL_VALIDATION) {
            return urlValidationPanel.activitySnapshot(activityId(), mode.title(), targetLabel());
        }

        ActivityState activityState;
        if (shuttingDown || sessionController.state() == SessionState.DISPOSED) {
            activityState = ActivityState.DISPOSED;
        } else if (resultsWorkspace != null && resultsWorkspace.isRetryRunning()) {
            activityState = resultsWorkspace.isRetryPaused() ? ActivityState.PAUSED : ActivityState.RETRYING;
        } else if (sessionController.state() == SessionState.RUNNING && !sessionController.isRunning()) {
            activityState = ActivityState.STOPPING;
        } else if (sessionController.state() == SessionState.RUNNING) {
            activityState = sessionController.isPaused() ? ActivityState.PAUSED : ActivityState.RUNNING;
        } else {
            activityState = switch (sessionController.state()) {
                case STOPPED -> ActivityState.STOPPED;
                case COMPLETED -> ActivityState.COMPLETED;
                case DISPOSED -> ActivityState.DISPOSED;
                default -> ActivityState.IDLE;
            };
        }
        int sent = resultsWorkspace == null ? 0 : resultsWorkspace.allResultsCount();
        return new ActivitySnapshot(activityId(), mode.title(), targetLabel(), activityState,
            sent + " result" + (sent == 1 ? "" : "s"), sent);
    }

    @Override
    public void pauseActivity() {
        if (mode == TargetedMode.IDOR) idorPanel.pauseActivity();
        else if (mode == TargetedMode.URL_VALIDATION) urlValidationPanel.pauseActivity();
        else if (resultsWorkspace != null && resultsWorkspace.isRetryRunning()) {
            resultsWorkspace.pauseThrottleRetry();
        } else if (sessionController.isRunning() && !sessionController.isPaused()) togglePause();
    }

    @Override
    public void resumeActivity() {
        if (mode == TargetedMode.IDOR) idorPanel.resumeActivity();
        else if (mode == TargetedMode.URL_VALIDATION) urlValidationPanel.resumeActivity();
        else if (resultsWorkspace != null && resultsWorkspace.isRetryRunning()) {
            resultsWorkspace.resumeThrottleRetry();
        } else if (sessionController.isRunning() && sessionController.isPaused()) togglePause();
    }

    @Override
    public void stopActivity() {
        if (mode == TargetedMode.IDOR) idorPanel.stopActivity();
        else if (mode == TargetedMode.URL_VALIDATION) urlValidationPanel.stopActivity();
        else if (resultsWorkspace != null && resultsWorkspace.isRetryRunning()) resultsWorkspace.stopThrottleRetry();
        else if (sessionController.state() == SessionState.RUNNING) stopFuzzing();
    }

    private String targetLabel() {
        return request.method() + " " + request.url();
    }

    public void stopFuzzing() {
        sessionController.stop();
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        pauseButton.setEnabled(false);
        statusLabel.setText("Stopping...");
    }

    public void cleanup() {
        shuttingDown = true;
        sessionController.dispose();
        if (resultsWorkspace != null) {
            resultsWorkspace.cleanup();
        }
        if (urlValidationPanel != null) {
            urlValidationPanel.cleanup();
        }
        if (idorPanel != null) {
            idorPanel.cleanup();
        }
        if (optionsDialog != null) {
            optionsDialog.dispose();
        }
    }

    private void initializeUi() {
        setLayout(new BorderLayout());
        add(buildModePanel(), BorderLayout.CENTER);

        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoPanel.add(new JLabel(String.format("Target: %s %s", request.method(), request.url())));
        add(infoPanel, BorderLayout.SOUTH);
    }

    private JPanel buildModePanel() {
        return switch (mode) {
            case BYPASS -> buildBypassTab();
            case IDOR -> {
                idorPanel = new IdorPanel(api, request, sessionController.globalGovernor());
                yield idorPanel;
            }
            case URL_VALIDATION -> {
                urlValidationPanel = new UrlValidationPanel(api, request, sessionController.globalGovernor());
                yield urlValidationPanel;
            }
        };
    }

    private JPanel buildBypassTab() {
        JPanel bypassPanel = new JPanel(new BorderLayout());
        bypassPanel.add(buildTopPanel(), BorderLayout.NORTH);
        bypassPanel.add(buildCenterPanel(), BorderLayout.CENTER);
        return bypassPanel;
    }

    private JPanel buildTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startButton = new JButton("Start Fuzzing");
        startButton.addActionListener(e -> startFuzzing());
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopFuzzing());
        pauseButton = new JButton("Pause");
        pauseButton.setEnabled(false);
        pauseButton.addActionListener(e -> togglePause());
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        optionsButton = new JButton("Options...");
        optionsButton.setToolTipText("Configure execution, throttling, headers, and Collaborator payloads.");
        optionsButton.addActionListener(e -> openOptionsDialog());
        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(pauseButton);
        controlPanel.add(clearButton);
        controlPanel.add(optionsButton);

        statusLabel = new JLabel("Ready. Target: " + request.method() + " " + request.url());
        warningLabel = new JLabel("");
        warningLabel.setForeground(new java.awt.Color(204, 102, 0));
        warningLabel.setVisible(false);

        attackSelectionPanel = new AttackSelectionPanel(config, () -> warningLabel.setVisible(false));
        runOptionsPanel = new RunOptionsPanel(config, isCollaboratorAvailable());

        JPanel topContent = new JPanel();
        topContent.setLayout(new BoxLayout(topContent, BoxLayout.Y_AXIS));

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.add(controlPanel, BorderLayout.WEST);
        topRow.add(statusLabel, BorderLayout.CENTER);
        topContent.add(topRow);

        JPanel warningRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        warningRow.add(warningLabel);
        topContent.add(warningRow);

        JPanel optionsRow = new JPanel(new BorderLayout());
        optionsRow.add(attackSelectionPanel, BorderLayout.CENTER);
        topContent.add(optionsRow);

        topPanel.add(topContent, BorderLayout.CENTER);
        return topPanel;
    }

    private void openOptionsDialog() {
        if (optionsDialog == null) {
            optionsDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Bypass Options", false);
            optionsDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);

            JPanel content = new JPanel(new BorderLayout(8, 8));
            content.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));
            content.add(runOptionsPanel, BorderLayout.CENTER);

            JButton closeButton = new JButton("Close");
            closeButton.addActionListener(e -> optionsDialog.setVisible(false));
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            buttons.add(closeButton);
            content.add(buttons, BorderLayout.SOUTH);

            optionsDialog.setContentPane(content);
            optionsDialog.pack();
            optionsDialog.setMinimumSize(new Dimension(520, 260));
        }
        optionsDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        optionsDialog.setVisible(true);
    }

    private JSplitPane buildCenterPanel() {
        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> api.logging().logToOutput(
                "Filters applied: showing " + workspace.shownResultsCount() + " of " + workspace.allResultsCount() + " results"
            ),
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.DEFAULT,
            false,
            sessionController.globalGovernor()
        );
        return resultsWorkspace.component();
    }

    private void startFuzzing() {
        if (resultsWorkspace.isRetryRunning()) {
            statusLabel.setText("Wait for the throttled-request retry pass to finish.");
            return;
        }
        SessionRunOptions runOptions = collectRunOptions();
        if (!runOptions.hasEnabledAttacks()) {
            warningLabel.setText("Please select at least one attack type before starting.");
            warningLabel.setVisible(true);
            return;
        }

        if (runOptions.collaboratorPayloads() && !isCollaboratorAvailable()) {
            int choice = JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "Burp Collaborator is not available.\n\nContinue fuzzing without Collaborator payloads?",
                "Collaborator Not Available",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );

            if (choice != JOptionPane.YES_OPTION) {
                return;
            }

            runOptionsPanel.setCollaboratorEnabled(false);
            runOptions = runOptions.withoutCollaboratorPayloads();
        }

        runOptions.applyTo(config);
        resultsWorkspace.configureThrottleRetries(runOptions.throttleSettings());
        resultsWorkspace.setPrimaryRunActive(true);
        warningLabel.setVisible(false);
        setAttackControlsEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("Fuzzing in progress...");

        List<String> warnings = preflightAnalyzer.analyze(request, runOptions);
        if (!warnings.isEmpty()) {
            warningLabel.setText("Note: " + String.join("; ", warnings));
            warningLabel.setVisible(true);
        }

        if (!sessionController.start()) {
            resultsWorkspace.setPrimaryRunActive(false);
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            setAttackControlsEnabled(true);
            statusLabel.setText("Unable to start fuzzing");
        } else {
            pauseButton.setText("Pause");
            pauseButton.setEnabled(true);
        }
    }

    private void togglePause() {
        if (!sessionController.isRunning()) return;
        if (sessionController.isPaused()) {
            sessionController.resume();
            pauseButton.setText("Pause");
            statusLabel.setText("Fuzzing resumed...");
        } else {
            sessionController.pause();
            pauseButton.setText("Resume");
            statusLabel.setText("Paused. Already-sent requests may still finish; no new requests will be sent.");
        }
    }

    private SessionRunOptions collectRunOptions() {
        return SessionRunOptionsSupport.collect(attackSelectionPanel, runOptionsPanel);
    }

    private void clearResults() {
        resultsWorkspace.clear();
        statusLabel.setText("Results cleared");
    }

    private void applyFilters() {
        resultsWorkspace.applyFilters();
    }

    private void addResult(AttackResult result) {
        SwingUtilities.invokeLater(() -> {
            try {
                resultsWorkspace.addResult(result);

                int totalSent = resultsWorkspace.allResultsCount();
                int showing = resultsWorkspace.shownResultsCount();
                statusLabel.setText(sessionController.isPaused()
                    ? "Paused (" + totalSent + " requests sent, showing " + showing + ")"
                    : sessionController.isRunning()
                        ? "Fuzzing... (" + totalSent + " requests sent, showing " + showing + ")"
                        : "Completed: " + totalSent + " requests sent, showing " + showing);

                if (!sessionController.isRunning()) {
                    startButton.setEnabled(true);
                    stopButton.setEnabled(false);
                    setAttackControlsEnabled(true);
                }

            } catch (Exception e) {
                api.logging().logToError("Error in addResult: " + e.getMessage());
            }
        });
    }

    private void handleSessionStateChange(SessionState state) {
        SwingUtilities.invokeLater(() -> {
            if (state == SessionState.RUNNING) {
                resultsWorkspace.setPrimaryRunActive(true);
                statusLabel.setText("Fuzzing in progress...");
                startButton.setEnabled(false);
                stopButton.setEnabled(true);
                pauseButton.setText("Pause");
                pauseButton.setEnabled(true);
                setAttackControlsEnabled(false);
                return;
            }

            if (shuttingDown && state != SessionState.DISPOSED) {
                return;
            }

            int totalSent = resultsWorkspace.allResultsCount();
            int showing = resultsWorkspace.shownResultsCount();

            switch (state) {
                case STOPPED -> {
                    resultsWorkspace.setPrimaryRunActive(false);
                    updateIdleUi("Stopped: " + totalSent + " requests sent, showing " + showing);
                }
                case COMPLETED -> {
                    resultsWorkspace.setPrimaryRunActive(false);
                    updateIdleUi("Completed: " + totalSent + " requests sent, showing " + showing);
                }
                case DISPOSED -> {
                    resultsWorkspace.setPrimaryRunActive(false);
                    startButton.setEnabled(false);
                    stopButton.setEnabled(false);
                    pauseButton.setEnabled(false);
                }
                default -> {
                }
            }
        });
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        pauseButton.setText("Pause");
        pauseButton.setEnabled(false);
        setAttackControlsEnabled(true);
    }

    private void setAttackControlsEnabled(boolean enabled) {
        if (shuttingDown) {
            return;
        }

        attackSelectionPanel.setControlsEnabled(enabled);
        runOptionsPanel.setControlsEnabled(enabled, isCollaboratorAvailable());
        optionsButton.setEnabled(enabled);
    }

    private boolean isCollaboratorAvailable() {
        return !shuttingDown && CollaboratorSupport.isAvailable(api);
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value == null ? "" : value;
        }
        return value.substring(0, maxLength - 3) + "...";
    }
}
