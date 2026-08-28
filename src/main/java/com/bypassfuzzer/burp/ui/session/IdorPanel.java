package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.idor.IdorDebugInfoBuilder;
import com.bypassfuzzer.burp.core.idor.IdorEngine;
import com.bypassfuzzer.burp.core.idor.IdorOptions;
import com.bypassfuzzer.burp.core.idor.IdorRequestMutator;
import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybook;
import com.bypassfuzzer.burp.core.idor.playbooks.IdorPlaybookRegistry;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.ui.dashboard.ActivitySnapshot;
import com.bypassfuzzer.burp.ui.dashboard.ActivityState;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dedicated session tab for IDOR/BOLA analysis.
 */
public class IdorPanel extends JPanel {

    private static final IdorRunOptions DEFAULT_RUN_OPTIONS = new IdorRunOptions(java.util.Set.of(429, 503));
    private static final Dimension PLAYBOOK_DIALOG_SIZE = new Dimension(820, 420);
    private static final Dimension DEBUG_DIALOG_SIZE = new Dimension(980, 720);

    private final MontoyaApi api;
    private final HttpRequest originalRequest;
    private final IdorEngine engine;
    private final IdorPlaybookRegistry playbookRegistry = new IdorPlaybookRegistry();
    private final IdorRequestMutator requestMutator = new IdorRequestMutator();
    private final IdorDebugInfoBuilder debugInfoBuilder = new IdorDebugInfoBuilder();
    private final GlobalTrafficGovernor globalGovernor;

    private JButton startButton;
    private JButton stopButton;
    private JButton pauseButton;
    private JButton configureButton;
    private JLabel statusLabel;
    private JLabel warningLabel;
    private JTextField authorizedIdentifierField;
    private JTextField targetIdentifierField;
    private IdorRunOptionsPanel runOptionsPanel;
    private SessionResultsWorkspace resultsWorkspace;
    private JDialog configDialog;
    private JLabel configWarningLabel;

    private volatile boolean shuttingDown = false;
    private volatile boolean stopRequested = false;
    private volatile boolean hasStarted = false;

    public IdorPanel(MontoyaApi api, HttpRequest request) {
        this(api, request, new GlobalTrafficGovernor());
    }

    public IdorPanel(MontoyaApi api, HttpRequest request, GlobalTrafficGovernor globalGovernor) {
        super(new BorderLayout());
        this.api = api;
        this.originalRequest = request;
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
        this.engine = new IdorEngine(api, this.globalGovernor);
        initializeUi();
        applyFilters();
    }

    public void cleanup() {
        shuttingDown = true;
        engine.cleanup();
        if (resultsWorkspace != null) {
            resultsWorkspace.cleanup();
        }
        if (configDialog != null) {
            configDialog.dispose();
        }
    }

    public ActivitySnapshot activitySnapshot(String id, String mode, String target) {
        ActivityState state;
        if (shuttingDown) state = ActivityState.DISPOSED;
        else if (resultsWorkspace.isRetryRunning()) {
            state = resultsWorkspace.isRetryPaused() ? ActivityState.PAUSED : ActivityState.RETRYING;
        } else if (engine.isRunning()) state = engine.isPaused() ? ActivityState.PAUSED : ActivityState.RUNNING;
        else if (stopRequested) state = ActivityState.STOPPED;
        else state = hasStarted ? ActivityState.COMPLETED : ActivityState.IDLE;
        long httpSent = totalHttpRequestsSent();
        int sent = (int) Math.min(Integer.MAX_VALUE, httpSent);
        int recorded = resultsWorkspace.allResultsCount();
        return new ActivitySnapshot(id, mode, target, state,
            recorded + " result" + (recorded == 1 ? "" : "s") + "; " + httpSent + " HTTP sent", sent);
    }

    public void pauseActivity() {
        if (resultsWorkspace.isRetryRunning()) {
            resultsWorkspace.pauseThrottleRetry();
            pauseButton.setText("Resume");
            statusLabel.setText(resultsWorkspace.retryStatusText());
        } else if (engine.isRunning() && !engine.isPaused()) togglePause();
    }

    public void resumeActivity() {
        if (resultsWorkspace.isRetryRunning()) {
            resultsWorkspace.resumeThrottleRetry();
            pauseButton.setText("Pause");
            statusLabel.setText(resultsWorkspace.retryStatusText());
        } else if (engine.isRunning() && engine.isPaused()) togglePause();
    }

    public void stopActivity() {
        if (resultsWorkspace.isRetryRunning()) resultsWorkspace.stopThrottleRetry();
        else if (engine.isRunning()) stopAnalysis();
    }

    private void initializeUi() {
        authorizedIdentifierField = new JTextField(18);
        targetIdentifierField = new JTextField(18);
        runOptionsPanel = new IdorRunOptionsPanel(DEFAULT_RUN_OPTIONS);
        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
    }

    private JPanel buildTopPanel() {
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopAnalysis());
        pauseButton = new JButton("Pause");
        pauseButton.setEnabled(false);
        pauseButton.addActionListener(e -> togglePause());
        configureButton = new JButton("Configure Attack");
        configureButton.addActionListener(e -> openConfigDialog());
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        JButton playbooksButton = new JButton("Playbooks");
        playbooksButton.setToolTipText("Open the current IDOR playbook reference.");
        JButton debugButton = new JButton("Debug Info");
        debugButton.setToolTipText("Open IDOR diagnostics and choose whether to copy or save them.");
        controlPanel.add(stopButton);
        controlPanel.add(pauseButton);
        controlPanel.add(configureButton);
        controlPanel.add(clearButton);
        controlPanel.add(playbooksButton);
        controlPanel.add(debugButton);
        playbooksButton.addActionListener(e -> showPlaybookReference());
        debugButton.addActionListener(e -> showDebugInfoDialog());

        statusLabel = new JLabel("Open Configure Attack to compare an authorized identifier with a target identifier.");
        warningLabel = new JLabel("");
        warningLabel.setForeground(new Color(204, 102, 0));
        warningLabel.setVisible(false);

        JPanel topContent = new JPanel();
        topContent.setLayout(new BoxLayout(topContent, BoxLayout.Y_AXIS));

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.add(controlPanel, BorderLayout.WEST);
        topRow.add(statusLabel, BorderLayout.CENTER);
        topContent.add(topRow);

        JPanel warningRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        warningRow.add(warningLabel);
        topContent.add(warningRow);

        topPanel.add(topContent, BorderLayout.CENTER);
        return topPanel;
    }

    private void openConfigDialog() {
        if (configDialog == null) {
            configDialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Configure IDOR Attack", false);
            configDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
            configDialog.setContentPane(buildConfigDialogContent());
            configDialog.pack();
            configDialog.setMinimumSize(new Dimension(720, 360));
        }
        configDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        configDialog.setVisible(true);
    }

    private JPanel buildConfigDialogContent() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(javax.swing.BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel identifierRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        identifierRow.add(new JLabel("Identifier 1 (authorized):"));
        identifierRow.add(authorizedIdentifierField);
        identifierRow.add(new JLabel("Identifier 2 (target):"));
        identifierRow.add(targetIdentifierField);
        content.add(identifierRow);

        JPanel replacementNote = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        replacementNote.add(new JLabel("Identifiers are replaced as exact literals across the request."));
        content.add(replacementNote);
        content.add(runOptionsPanel);

        configWarningLabel = new JLabel("");
        configWarningLabel.setForeground(new Color(204, 102, 0));
        configWarningLabel.setVisible(false);
        JPanel warningRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        warningRow.add(configWarningLabel);
        content.add(warningRow);

        startButton = new JButton("Start IDOR Analysis");
        startButton.addActionListener(e -> startAnalysis());
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> configDialog.setVisible(false));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(startButton);
        buttons.add(closeButton);
        content.add(buttons);
        return content;
    }

    private void showPlaybookReference() {
        JTextArea summary = new JTextArea(
            "This tab runs IDOR-specific playbooks.\n"
                + "Control and unauthorized baseline requests always run first.\n\n"
                + formatPlaybookSummary()
        );
        summary.setEditable(false);
        summary.setFocusable(false);
        summary.setLineWrap(true);
        summary.setWrapStyleWord(true);
        summary.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(summary);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setPreferredSize(PLAYBOOK_DIALOG_SIZE);

        JOptionPane.showMessageDialog(
            api.userInterface().swingUtils().suiteFrame(),
            scrollPane,
            "Current IDOR Playbooks",
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    private void showDebugInfoDialog() {
        try {
            String authorizedIdentifier = authorizedIdentifierField.getText() == null ? "" : authorizedIdentifierField.getText().trim();
            String targetIdentifier = targetIdentifierField.getText() == null ? "" : targetIdentifierField.getText().trim();
            IdorOptions options = new IdorOptions(authorizedIdentifier, targetIdentifier, runOptionsPanel.collect());
            String debugInfo = debugInfoBuilder.build(originalRequest, options);
            openDebugInfoDialog(debugInfo, authorizedIdentifier, targetIdentifier);
            hideWarning();
        } catch (Exception e) {
            showWarning("Unable to build debug info: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void openDebugInfoDialog(String debugInfo, String authorizedIdentifier, String targetIdentifier) {
        JTextArea debugArea = new JTextArea(debugInfo);
        debugArea.setEditable(false);
        debugArea.setFocusable(true);
        debugArea.setCaretPosition(0);
        debugArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        debugArea.setLineWrap(false);
        debugArea.setWrapStyleWord(false);

        JScrollPane scrollPane = new JScrollPane(debugArea);
        scrollPane.setPreferredSize(DEBUG_DIALOG_SIZE);

        JDialog dialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "IDOR Debug Info", true);
        dialog.setLayout(new BorderLayout());
        dialog.add(scrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton copyButton = new JButton("Copy to Clipboard");
        JButton saveButton = new JButton("Save to File");
        JButton closeButton = new JButton("Close");
        buttonPanel.add(copyButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        copyButton.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(debugInfo), null);
            statusLabel.setText("Copied IDOR debug info (" + debugInfo.length() + " chars) to clipboard.");
        });
        saveButton.addActionListener(e -> saveDebugInfoToFile(dialog, debugInfo, authorizedIdentifier, targetIdentifier));
        closeButton.addActionListener(e -> dialog.dispose());

        dialog.pack();
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        dialog.setVisible(true);
    }

    private void saveDebugInfoToFile(JDialog parentDialog,
                                     String debugInfo,
                                     String authorizedIdentifier,
                                     String targetIdentifier) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save IDOR Debug Info");
        chooser.setSelectedFile(new java.io.File(defaultDebugFilename(authorizedIdentifier, targetIdentifier)));

        int result = chooser.showSaveDialog(parentDialog);
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }

        java.io.File file = chooser.getSelectedFile();
        if (file.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(
                parentDialog,
                "Overwrite existing file?\n" + file.getAbsolutePath(),
                "Confirm Save",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            if (overwrite != JOptionPane.YES_OPTION) {
                return;
            }
        }

        try {
            Files.writeString(file.toPath(), debugInfo, StandardCharsets.UTF_8);
            statusLabel.setText("Saved IDOR debug info to " + file.getAbsolutePath());
        } catch (Exception e) {
            showWarning("Unable to save debug info: " + e.getMessage());
        }
    }

    private String defaultDebugFilename(String authorizedIdentifier, String targetIdentifier) {
        String authorized = sanitizeFilenamePart(authorizedIdentifier);
        String target = sanitizeFilenamePart(targetIdentifier);
        return "idor-debug-" + authorized + "-to-" + target + ".txt";
    }

    private String sanitizeFilenamePart(String value) {
        if (value == null || value.isBlank()) {
            return "blank";
        }
        return value.replaceAll("[^A-Za-z0-9._-]+", "_");
    }

    private String formatPlaybookSummary() {
        Map<String, List<IdorPlaybook>> grouped = new LinkedHashMap<>();
        grouped.put("Path playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.path."))
            .toList());
        grouped.put("Query playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.query."))
            .toList());
        grouped.put("Body playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.body."))
            .toList());
        grouped.put("Hybrid playbooks", playbookRegistry.all().stream()
            .filter(playbook -> playbook.id().startsWith("idor.hybrid."))
            .toList());

        StringBuilder summary = new StringBuilder("Current playbooks:\n\n");
        for (Map.Entry<String, List<IdorPlaybook>> entry : grouped.entrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }

            summary.append(entry.getKey()).append('\n');
            for (IdorPlaybook playbook : entry.getValue()) {
                summary.append(" - ")
                    .append(playbook.displayName())
                    .append(": ")
                    .append(compactSummary(playbook.id()))
                    .append('\n');
            }
            summary.append('\n');
        }
        summary.append("Add new technique families in core/idor/playbooks/ and register them in IdorPlaybookRegistry.");
        return summary.toString();
    }

    private String compactSummary(String playbookId) {
        return switch (playbookId) {
            case "idor.path.suffix_formats" -> ".json/.html and similar suffix variants";
            case "idor.path.trailing_slash" -> "add or remove the final slash";
            case "idor.path.special_identifier_values" -> "sentinel values like 0, 1, -1, and odd characters";
            case "idor.path.dot_segments" -> "authorized-id/../target-id style dot-segment tricks";
            case "idor.query.conflicting_identifiers" -> "mix target path IDs with conflicting query IDs";
            case "idor.query.parameter_pollution" -> "duplicate identifier params in different orders";
            case "idor.query.comma_separated_identifiers" -> "comma-separated lists like target,authorized";
            case "idor.query.json_wrap" -> "query values wrapped as small JSON objects";
            case "idor.query.identifier_aliases" -> "common alternate param names like id, userId, accountId";
            case "idor.query.numeric_pivots" -> "numeric pivots such as 0, 1, 2, 3, and -1";
            case "idor.body.content_type_tampering" -> "move the ID across urlencoded, JSON, XML, and multipart bodies";
            case "idor.body.json_wrap" -> "wrap JSON IDs as nested objects";
            case "idor.body.deserialization_hints" -> "type-hinted and prototype-like JSON object wrappers";
            case "idor.body.json_batch_identifiers" -> "JSON arrays mixing target and authorized IDs";
            case "idor.body.json_parameter_pollution" -> "repeat JSON identifier keys in both orders";
            case "idor.body.wildcard_identifiers" -> "wildcards such as *, %, _, and .";
            case "idor.body.unexpected_data_types" -> "booleans, nulls, numbers, arrays, and operator-like objects";
            case "idor.hybrid.trailing_control_characters" -> "control bytes, null bytes, and encoded whitespace";
            case "idor.hybrid.empty_identifier_values" -> "empty, blank, null, and undefined values";
            case "idor.hybrid.case_variants" -> "uppercase, lowercase, and alternating-case IDs";
            case "idor.hybrid.canonical_identifier_formats" -> "compact, braced, and canonical UUID forms";
            case "idor.hybrid.uuid_neighbor_edits" -> "small last-byte and last-quartet UUID/hex edits";
            case "idor.hybrid.truncated_identifier_variants" -> "shortened, zero-padded, and all-zero variants";
            case "idor.hybrid.uuid_version_variants" -> "UUID v1/v3/v4/v5-style version swaps";
            case "idor.hybrid.accept_negotiation" -> "representation-specific Accept header variants";
            case "idor.hybrid.cross_source_conflicts" -> "path/query combinations where different sources disagree";
            case "idor.hybrid.identifier_encoding" -> "URL, double-URL, braced, and base64-style encodings";
            case "idor.hybrid.method_override" -> "CRUD methods plus curated method-override headers";
            default -> playbookRegistry.all().stream()
                .filter(playbook -> playbook.id().equals(playbookId))
                .map(IdorPlaybook::description)
                .findFirst()
                .orElse("");
        };
    }

    private JSplitPane buildCenterPanel() {
        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> api.logging().logToOutput(
                "IDOR filters applied: showing " + workspace.shownResultsCount() + " of " + workspace.allResultsCount() + " results"
            ),
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.IDOR,
            false,
            globalGovernor
        );
        resultsWorkspace.setResultsChangedListener(ignored -> updateResultStatus());
        return resultsWorkspace.component();
    }

    private void startAnalysis() {
        if (resultsWorkspace.isRetryRunning()) {
            statusLabel.setText("Wait for the throttled-request retry pass to finish.");
            return;
        }
        IdorOptions options = collectOptions();
        if (options == null) {
            return;
        }

        if (requestMutator.countOccurrences(originalRequest, options.normalizedAuthorizedIdentifier()) == 0) {
            showWarning("Identifier 1 was not found in the current request.");
            return;
        }

        hideWarning();
        stopRequested = false;
        setControlsEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("IDOR analysis in progress...");
        resultsWorkspace.configureThrottleRetries(options.runOptions().throttleSettings());
        resultsWorkspace.setPrimaryRunActive(true);

        boolean started = engine.start(originalRequest, options, this::addResult, this::handleCompletion);
        if (!started) {
            resultsWorkspace.setPrimaryRunActive(false);
            updateIdleUi("Unable to start IDOR analysis");
        } else {
            hasStarted = true;
            pauseButton.setText("Pause");
            pauseButton.setEnabled(true);
            if (configDialog != null) {
                configDialog.setVisible(false);
            }
        }
    }

    private void togglePause() {
        if (!engine.isRunning()) return;
        if (engine.isPaused()) {
            engine.resume();
            pauseButton.setText("Pause");
            statusLabel.setText("IDOR analysis resumed...");
        } else {
            engine.pause();
            pauseButton.setText("Resume");
            statusLabel.setText("Paused. Already-sent requests may still finish; no new requests will be sent.");
        }
    }

    private void stopAnalysis() {
        stopRequested = true;
        engine.stop();
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        pauseButton.setEnabled(false);
        statusLabel.setText("Stopping IDOR analysis...");
    }

    private IdorOptions collectOptions() {
        IdorRunOptions runOptions = runOptionsPanel.collect();

        String authorizedIdentifier = authorizedIdentifierField.getText() == null ? "" : authorizedIdentifierField.getText().trim();
        String targetIdentifier = targetIdentifierField.getText() == null ? "" : targetIdentifierField.getText().trim();

        if (authorizedIdentifier.isEmpty()) {
            showWarning("Enter identifier 1 before starting.");
            return null;
        }

        if (targetIdentifier.isEmpty()) {
            showWarning("Enter identifier 2 before starting.");
            return null;
        }

        if (authorizedIdentifier.equals(targetIdentifier)) {
            showWarning("Identifier 1 and identifier 2 must be different.");
            return null;
        }

        return new IdorOptions(authorizedIdentifier, targetIdentifier, runOptions);
    }

    private void clearResults() {
        resultsWorkspace.clear();
        statusLabel.setText("Results cleared");
    }

    private void applyFilters() {
        resultsWorkspace.applyFilters();
    }

    private void addResult(AttackResult result) {
        resultsWorkspace.enqueueResult(result);
    }

    private void updateResultStatus() {
        long totalSent = totalHttpRequestsSent();
        int recorded = resultsWorkspace.allResultsCount();
        int showing = resultsWorkspace.shownResultsCount();
        statusLabel.setText(engine.isPaused()
            ? "Paused (" + metrics(totalSent, recorded, showing) + ")"
            : engine.isRunning()
                ? "IDOR analysis... (" + metrics(totalSent, recorded, showing) + ")"
                : "Completed: " + metrics(totalSent, recorded, showing));
    }

    private void handleCompletion() {
        resultsWorkspace.afterPendingResults(() -> {
            resultsWorkspace.setPrimaryRunActive(false);
            if (shuttingDown) {
                if (startButton != null) {
                    startButton.setEnabled(false);
                }
                stopButton.setEnabled(false);
                pauseButton.setEnabled(false);
                return;
            }

            long totalSent = totalHttpRequestsSent();
            int recorded = resultsWorkspace.allResultsCount();
            int showing = resultsWorkspace.shownResultsCount();
            updateIdleUi((stopRequested ? "Stopped: " : "Completed: ")
                + metrics(totalSent, recorded, showing));
        });
    }

    private long totalHttpRequestsSent() {
        return engine.httpRequestsSent() + resultsWorkspace.retryRequestCount();
    }

    private String metrics(long sent, int recorded, int showing) {
        return sent + " HTTP request(s) sent; " + recorded + " result(s) recorded"
            + (showing == recorded ? "" : ", showing " + showing);
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        if (startButton != null) {
            startButton.setEnabled(true);
        }
        stopButton.setEnabled(false);
        pauseButton.setText("Pause");
        pauseButton.setEnabled(false);
        setControlsEnabled(true);
    }

    private void setControlsEnabled(boolean enabled) {
        if (shuttingDown) {
            return;
        }

        authorizedIdentifierField.setEnabled(enabled);
        targetIdentifierField.setEnabled(enabled);
        runOptionsPanel.setControlsEnabled(enabled);
        configureButton.setEnabled(enabled);
    }

    private void showWarning(String message) {
        warningLabel.setText(message);
        warningLabel.setVisible(true);
        if (configWarningLabel != null) {
            configWarningLabel.setText(message);
            configWarningLabel.setVisible(true);
        }
    }

    private void hideWarning() {
        warningLabel.setVisible(false);
        if (configWarningLabel != null) {
            configWarningLabel.setVisible(false);
        }
    }
}
