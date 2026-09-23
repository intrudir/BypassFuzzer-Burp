package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.idor.IdorEngine;
import com.bypassfuzzer.burp.core.idor.IdorOptions;
import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.burp.http.CoreRequestAdapter;
import com.bypassfuzzer.burp.http.ConfiguredHeaderPolicy;
import com.bypassfuzzer.core.scan.IdentifierLocation;
import com.bypassfuzzer.core.scan.IdentifierLocationSpan;
import com.bypassfuzzer.core.scan.IdorPlanOptions;
import com.bypassfuzzer.core.scan.IdorPlanner;
import com.bypassfuzzer.core.scan.PairedControlSeparatorPlanner;
import com.bypassfuzzer.core.scan.PlannedRequest;
import com.bypassfuzzer.core.scan.ResponseGuidedIdorPlanner;
import com.bypassfuzzer.core.http.HttpHeader;
import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
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
import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

/**
 * Dedicated session tab for IDOR/BOLA analysis.
 */
public class IdorPanel extends JPanel {

    private static final IdorRunOptions DEFAULT_RUN_OPTIONS = new IdorRunOptions(java.util.Set.of(429, 503));
    private static final Dimension PLAYBOOK_DIALOG_SIZE = new Dimension(820, 420);
    private static final Dimension DEBUG_DIALOG_SIZE = new Dimension(980, 720);

    private final MontoyaApi api;
    private final HttpRequest originalRequest;
    private final HttpResponse capturedResponse;
    private final IdorEngine engine;
    private final GlobalTrafficGovernor globalGovernor;

    private JButton startButton;
    private JButton stopButton;
    private JButton pauseButton;
    private JButton configureButton;
    private JLabel statusLabel;
    private JLabel warningLabel;
    private JTextField authorizedIdentifierField;
    private JTextField targetIdentifierField;
    private JComboBox<String> locationField;
    private JLabel mutationCoverageNote;
    private JTextField uniqueJsonPointerField;
    private final String uniqueToken = java.util.UUID.randomUUID().toString().substring(0, 8);
    private JCheckBox includeMethodChanges;
    private java.util.Set<String> selectedFamilies =
        new java.util.LinkedHashSet<>(new IdorPlanner().defaultFamilies());
    private JLabel responseFieldsLabel;
    private IdorRunOptionsPanel runOptionsPanel;
    private SessionResultsWorkspace resultsWorkspace;
    private JDialog configDialog;
    private JLabel configWarningLabel;
    private HttpRequestEditor configRequestEditor;
    private List<IdentifierLocation> discoveredLocations = List.of();

    private volatile boolean shuttingDown = false;
    private volatile boolean stopRequested = false;
    private volatile boolean hasStarted = false;

    public IdorPanel(MontoyaApi api, HttpRequest request) {
        this(api, request, null, new GlobalTrafficGovernor());
    }

    public IdorPanel(MontoyaApi api, HttpRequest request, GlobalTrafficGovernor globalGovernor) {
        this(api, request, null, globalGovernor);
    }

    public IdorPanel(MontoyaApi api, HttpRequest request, HttpResponse capturedResponse,
                     GlobalTrafficGovernor globalGovernor) {
        super(new BorderLayout());
        this.api = api;
        this.originalRequest = request;
        this.capturedResponse = capturedResponse;
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
        locationField = new JComboBox<>();
        mutationCoverageNote = new JLabel("All applicable mutations from selected playbooks are planned; preview the request count before running."
            + ("GET".equalsIgnoreCase(originalRequest.method())
                || "HEAD".equalsIgnoreCase(originalRequest.method())
                ? "" : " This request may change data."));
        uniqueJsonPointerField = new JTextField(18);
        includeMethodChanges = new JCheckBox("Include method changes and overrides");
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
            configDialog.setMinimumSize(new Dimension(950, 700));
        }
        configDialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        configDialog.setVisible(true);
    }

    private JPanel buildConfigDialogContent() {
        JPanel content = new JPanel(new BorderLayout(0, 6));
        content.setBorder(javax.swing.BorderFactory.createEmptyBorder(12, 12, 12, 12));
        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));

        JPanel identifierRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        identifierRow.add(new JLabel("Identifier 1 (authorized):"));
        identifierRow.add(authorizedIdentifierField);
        identifierRow.add(new JLabel("Identifier 2 (target):"));
        identifierRow.add(targetIdentifierField);
        controls.add(identifierRow);

        JPanel locationRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        locationRow.add(new JLabel("Identifier location:"));
        locationField.setPrototypeDisplayValue("json:/long/nested/identifier/path");
        locationField.addActionListener(e -> updateRequestHighlights());
        locationRow.add(locationField);
        JButton findLocations = new JButton("Find Locations");
        findLocations.addActionListener(e -> refreshLocations());
        locationRow.add(findLocations);
        controls.add(locationRow);

        JPanel limitRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        limitRow.add(includeMethodChanges);
        JButton families = new JButton("Select Playbooks...");
        families.addActionListener(e -> chooseFamilies());
        limitRow.add(families);
        JButton preview = new JButton("Preview Requests");
        preview.addActionListener(e -> previewRequests());
        limitRow.add(preview);
        controls.add(limitRow);
        JPanel coverageNoteRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        coverageNoteRow.add(mutationCoverageNote);
        controls.add(coverageNoteRow);
        JPanel uniqueRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        uniqueRow.add(new JLabel("Unique JSON string field (optional):"));
        uniqueJsonPointerField.setToolTipText("JSON pointer such as /name; adds a distinct run value to each request.");
        uniqueRow.add(uniqueJsonPointerField);
        controls.add(uniqueRow);
        JPanel responseRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        responseFieldsLabel = new JLabel("Response fields: enter identifiers to inspect captured JSON.");
        responseRow.add(responseFieldsLabel);
        JButton inspectFields = new JButton("Inspect Response Fields");
        inspectFields.addActionListener(e -> showResponseFields());
        responseRow.add(inspectFields);
        controls.add(responseRow);
        controls.add(runOptionsPanel);

        configWarningLabel = new JLabel("");
        configWarningLabel.setForeground(new Color(204, 102, 0));
        configWarningLabel.setVisible(false);
        JPanel warningRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        warningRow.add(configWarningLabel);
        controls.add(warningRow);
        content.add(controls, BorderLayout.NORTH);

        configRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        configRequestEditor.setRequest(originalRequest);
        JPanel editorPanel = new JPanel(new BorderLayout());
        editorPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Original request"));
        editorPanel.add(configRequestEditor.uiComponent(), BorderLayout.CENTER);
        editorPanel.setPreferredSize(new Dimension(950, 390));
        content.add(editorPanel, BorderLayout.CENTER);
        authorizedIdentifierField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { identifierChanged(); }
            @Override public void removeUpdate(DocumentEvent event) { identifierChanged(); }
            @Override public void changedUpdate(DocumentEvent event) { identifierChanged(); }
        });
        targetIdentifierField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { updateResponseFieldsLabel(); }
            @Override public void removeUpdate(DocumentEvent event) { updateResponseFieldsLabel(); }
            @Override public void changedUpdate(DocumentEvent event) { updateResponseFieldsLabel(); }
        });
        updateResponseFieldsLabel();

        startButton = new JButton("Start IDOR Analysis");
        startButton.addActionListener(e -> startAnalysis());
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> configDialog.setVisible(false));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(startButton);
        buttons.add(closeButton);
        content.add(buttons, BorderLayout.SOUTH);
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
        IdorOptions options = collectOptions();
        if (options == null) return;
        try {
            String debugInfo = formatPlan(options);
            openDebugInfoDialog(debugInfo, options.normalizedAuthorizedIdentifier(),
                options.normalizedTargetIdentifier());
            hideWarning();
        } catch (RuntimeException error) {
            showWarning("Unable to build debug info: " + error.getMessage());
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
        StringBuilder summary = new StringBuilder("Current IDOR families from the shared core:\n\n");
        IdorPlanner planner = new IdorPlanner();
        for (String id : planner.availableFamilies()) {
            summary.append(" - ").append(id);
            if (planner.dangerousFamilyRisks().containsKey(id))
                summary.append(" (DANGEROUS; off by default)");
            summary.append('\n');
        }
        summary.append("\nUse Preview Requests to inspect the requests selected for this run.");
        return summary.toString();
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

        java.util.List<IdentifierLocation> matches = IdentifierLocation.discover(
            new CoreRequestAdapter().fromMontoya(originalRequest), authorizedIdentifier);
        if (matches.isEmpty()) {
            showWarning("Identifier 1 was not found in a selectable request location.");
            return null;
        }
        if (matches.size() > 1 && locationField.getSelectedItem() == null) {
            refreshLocations();
            showWarning("Choose the exact identifier location before starting.");
            return null;
        }
        String key = matches.size() == 1 ? matches.get(0).key() : (String) locationField.getSelectedItem();
        if (matches.stream().noneMatch(item -> item.key().equals(key))) {
            refreshLocations();
            showWarning("Selected location no longer matches identifier 1.");
            return null;
        }
        IdorOptions options = new IdorOptions(authorizedIdentifier, targetIdentifier, runOptions, key,
            selectedFamilies, IdorPlanOptions.UNLIMITED, includeMethodChanges.isSelected(),
            uniqueJsonPointerField.getText().trim(), uniqueToken);
        try {
            new IdorPlanner().plan(new CoreRequestAdapter().fromMontoya(originalRequest),
                new IdorPlanOptions(authorizedIdentifier, targetIdentifier, key, selectedFamilies,
                    options.maxMutations(), options.includeMethodChanges(), options.uniqueJsonPointer(),
                    options.uniqueToken()));
        } catch (RuntimeException error) {
            showWarning("Unable to plan IDOR requests: " + error.getMessage());
            return null;
        }
        return options;
    }

    private void refreshLocations() {
        String value = authorizedIdentifierField.getText().trim();
        discoveredLocations = List.of();
        locationField.removeAllItems();
        if (value.isEmpty()) {
            updateRequestHighlights();
            return;
        }
        discoveredLocations = IdentifierLocation.discover(
            new CoreRequestAdapter().fromMontoya(originalRequest), value);
        for (IdentifierLocation location : discoveredLocations) locationField.addItem(location.key());
        if (locationField.getItemCount() > 1) locationField.setSelectedIndex(-1);
        updateRequestHighlights();
    }

    private void updateRequestHighlights() {
        if (configRequestEditor == null) return;
        String value = authorizedIdentifierField.getText().trim();
        configRequestEditor.setSearchExpression(value);
        IdentifierLocation selected = discoveredLocations.stream()
            .filter(location -> location.key().equals(locationField.getSelectedItem()))
            .findFirst().orElse(discoveredLocations.isEmpty() ? null : discoveredLocations.get(0));
        if (selected == null) return;
        HttpRequestData request = new CoreRequestAdapter().fromMontoya(originalRequest);
        IdentifierLocationSpan.find(request, selected).ifPresent(span -> focusRequestOffset(span.start()));
    }

    private void identifierChanged() {
        discoveredLocations = List.of();
        locationField.removeAllItems();
        updateRequestHighlights();
        updateResponseFieldsLabel();
    }

    private void focusRequestOffset(int offset) {
        try {
            HttpRequestEditor.class.getMethod("setCaretPosition", int.class).invoke(configRequestEditor, offset);
        } catch (ReflectiveOperationException ignored) {
            // Older Montoya versions still support the native editor's search highlighting.
        }
    }

    private void chooseFamilies() {
        IdorPlanner planner = new IdorPlanner();
        java.util.List<String> ids = planner.availableFamilies();
        JPanel choices = new JPanel();
        choices.setLayout(new BoxLayout(choices, BoxLayout.Y_AXIS));
        java.util.List<JCheckBox> boxes = new java.util.ArrayList<>();
        for (String id : ids) {
            String risk = planner.dangerousFamilyRisks().get(id);
            JCheckBox box = new JCheckBox(risk != null
                ? id + " — DANGEROUS: may probe other identifiers" : id,
                selectedFamilies.contains(id));
            box.setActionCommand(id);
            if (risk != null) {
                box.setName(id.equals(IdorPlanner.NUMERIC_PIVOTS_FAMILY)
                    ? "idorNumericPivotsCheckbox" : "idorDangerousFamilyCheckbox:" + id);
                box.setToolTipText(risk);
                box.setForeground(new Color(180, 40, 30));
            }
            boxes.add(box);
            choices.add(box);
        }
        JScrollPane scroller = new JScrollPane(choices);
        scroller.setPreferredSize(new Dimension(480, 400));
        if (JOptionPane.showConfirmDialog(configDialog, scroller, "Select IDOR Playbooks",
            JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        java.util.Set<String> next = new java.util.LinkedHashSet<>();
        for (JCheckBox box : boxes) if (box.isSelected()) next.add(box.getActionCommand());
        if (next.isEmpty()) { showWarning("Select at least one playbook."); return; }
        java.util.List<String> newlyEnabled = newlyEnabledDangerousFamilies(selectedFamilies, next);
        if (!newlyEnabled.isEmpty()) {
            String risks = newlyEnabled.stream().map(id -> id + ": " + planner.dangerousFamilyRisks().get(id))
                .collect(java.util.stream.Collectors.joining("\n\n"));
            int confirmed = JOptionPane.showConfirmDialog(configDialog,
                risks + "\n\nEnable these DANGEROUS playbooks?",
                "DANGEROUS: IDOR identifier probes", JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
            if (confirmed != JOptionPane.YES_OPTION) return;
        }
        selectedFamilies = next;
        hideWarning();
    }

    static java.util.List<String> newlyEnabledDangerousFamilies(java.util.Set<String> current,
                                                                java.util.Set<String> next) {
        IdorPlanner planner = new IdorPlanner();
        return planner.availableFamilies().stream().filter(id -> planner.dangerousFamilyRisks().containsKey(id)
            && !current.contains(id) && next.contains(id)).toList();
    }

    private void previewRequests() {
        IdorOptions options = collectOptions();
        if (options == null) return;
        try {
            List<PlannedRequest> planned = plannedRequests(options);
            List<RequestPreviewPanel.Row> rows = buildPreviewRows(options, planned);
            boolean awaitingResponse = (options.selectedFamilies().isEmpty()
                || options.selectedFamilies().contains(ResponseGuidedIdorPlanner.FAMILY))
                && capturedResponse == null;
            var coverage = new IdorPlanner().separatorCoverage(
                new CoreRequestAdapter().fromMontoya(originalRequest),
                new IdorPlanOptions(options.normalizedAuthorizedIdentifier(),
                    options.normalizedTargetIdentifier(), options.locationKey(), options.selectedFamilies(),
                    options.maxMutations(), options.includeMethodChanges()), planned);
            String separatorSummary = coverage == null ? "" : "\nPaired control separators: "
                + coverage.planned() + "/" + coverage.eligible() + " planned"
                + (coverage.notes().isEmpty() ? "" : "\n" + String.join("\n", coverage.notes()));
            RequestPreviewPanel.open(api, configDialog, "IDOR Request Preview",
                rows.size() + " planned requests, including authorized and target baselines; "
                    + "all applicable mutations from selected playbooks"
                    + (awaitingResponse ? "; response-guided probes require live baselines" : "")
                    + separatorSummary, rows);
        } catch (RuntimeException error) { showWarning("Unable to preview requests: " + error.getMessage()); }
    }

    List<RequestPreviewPanel.Row> buildPreviewRows(IdorOptions options) {
        return buildPreviewRows(options, plannedRequests(options));
    }

    private List<RequestPreviewPanel.Row> buildPreviewRows(IdorOptions options,
                                                            List<PlannedRequest> planned) {
        CoreRequestAdapter adapter = new CoreRequestAdapter();
        ConfiguredHeaderPolicy headers = new ConfiguredHeaderPolicy(options.runOptions().requestHeaders(),
            options.runOptions().userAgentMode(), options.runOptions().userAgentRandomizationSeed());
        IdentifierLocation location = IdentifierLocation.discover(adapter.fromMontoya(originalRequest),
            options.normalizedAuthorizedIdentifier()).stream()
            .filter(item -> item.key().equals(options.locationKey())).findFirst().orElseThrow();
        return planned.stream().map(item -> {
            HttpRequestData request = item.request();
            String raw = request.toRaw();
            String payload = item.family().equals(ResponseGuidedIdorPlanner.FAMILY)
                || item.family().equals(PairedControlSeparatorPlanner.FAMILY)
                ? item.payload() : location.byteOffset() >= 0
                ? item.baseline() ? (item.payload().equals("idor.baseline.control")
                    ? options.normalizedAuthorizedIdentifier() : options.normalizedTargetIdentifier())
                    : item.payload() : IdentifierLocationSpan.find(request, location)
                    .map(span -> raw.substring(span.start(), span.end())).orElse(item.payload());
            HttpRequest wire = headers.reconcileMutation(originalRequest,
                adapter.toMontoya(originalRequest, request));
            String stage = item.baseline()
                ? (item.payload().equals("idor.baseline.control") ? "Control" : "Target baseline")
                : "Mutation";
            return new RequestPreviewPanel.Row(stage, item.family(), payload,
                item.payload(), item.encoding(), wire);
        }).toList();
    }

    private List<PlannedRequest> plannedRequests(IdorOptions options) {
        var input = new CoreRequestAdapter().fromMontoya(originalRequest);
        IdorPlanOptions planOptions = new IdorPlanOptions(
            options.normalizedAuthorizedIdentifier(), options.normalizedTargetIdentifier(),
            options.locationKey(), options.selectedFamilies(), options.maxMutations(),
            options.includeMethodChanges(), options.uniqueJsonPointer(), options.uniqueToken());
        ResponseGuidedIdorPlanner guided = new ResponseGuidedIdorPlanner();
        return guided.enabled(planOptions)
            ? guided.plan(input, planOptions, capturedResponseData(), null)
            : new IdorPlanner().plan(input, planOptions);
    }

    private HttpResponseData capturedResponseData() {
        if (capturedResponse == null) return null;
        return new HttpResponseData(com.bypassfuzzer.core.http.HttpProtocol.AUTO,
            capturedResponse.statusCode(), capturedResponse.headers().stream()
                .map(header -> new HttpHeader(header.name(), header.value())).toList(),
            capturedResponse.body() == null ? new byte[0] : capturedResponse.body().getBytes(), 0);
    }

    private void updateResponseFieldsLabel() {
        if (responseFieldsLabel == null) return;
        if (capturedResponse == null) {
            responseFieldsLabel.setText("Response fields: no response was attached to this request.");
            return;
        }
        var fields = new ResponseGuidedIdorPlanner().discover(capturedResponseData(), null,
            authorizedIdentifierField.getText().trim(), targetIdentifierField.getText().trim());
        boolean targetOnly = !fields.isEmpty() && fields.stream().noneMatch(field ->
            authorizedIdentifierField.getText().trim().equals(field.value()));
        responseFieldsLabel.setText("Response fields matching either identifier: " + fields.size()
            + (targetOnly ? " (captured response matches only identifier 2; live baselines decide)" : ""));
    }

    private void showResponseFields() {
        updateResponseFieldsLabel();
        if (capturedResponse == null) {
            JOptionPane.showMessageDialog(configDialog, "Send a request with its response to IDOR to preview response-guided probes.");
            return;
        }
        var fields = new ResponseGuidedIdorPlanner().discover(capturedResponseData(), null,
            authorizedIdentifierField.getText().trim(), targetIdentifierField.getText().trim());
        String detail = fields.isEmpty() ? "No exact JSON identifier values found."
            : fields.stream().map(field -> field.pointer() + " (" + (field.numeric() ? "number" : "string")
                + ", identifier " + (authorizedIdentifierField.getText().trim().equals(field.value()) ? "1" : "2") + ")")
                .collect(java.util.stream.Collectors.joining("\n"));
        JOptionPane.showMessageDialog(configDialog, detail, "Response identifier fields",
            JOptionPane.INFORMATION_MESSAGE);
    }

    private String formatPlan(IdorOptions options) {
        var plan = plannedRequests(options);
        StringBuilder detail = new StringBuilder(plan.size() + " requests, including two controls\n\n");
        for (var item : plan) detail.append(item.payload()).append("\n")
            .append(item.request().toRaw()).append("\n\n");
        return detail.toString();
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
            if (!stopRequested && engine.lastDiagnostic() != null) {
                showWarning(engine.lastDiagnostic());
            }
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
        locationField.setEnabled(enabled);
        includeMethodChanges.setEnabled(enabled);
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
