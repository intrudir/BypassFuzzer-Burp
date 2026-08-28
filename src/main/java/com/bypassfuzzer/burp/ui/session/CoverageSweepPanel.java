package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepCandidate;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepAuthSelection;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepEngine;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepMode;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepOptions;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPayloadSet;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepProbe;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPreview;
import com.bypassfuzzer.burp.http.UserAgentMode;
import com.bypassfuzzer.burp.core.coverage.PostmanCollectionParser;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.ui.dashboard.ActivitySnapshot;
import com.bypassfuzzer.burp.ui.dashboard.ActivityState;
import com.bypassfuzzer.burp.ui.dashboard.ManagedActivity;
import com.google.gson.Gson;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.SwingUtilities;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.WindowConstants;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Window;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;

public class CoverageSweepPanel extends JPanel implements ManagedActivity {

    private final MontoyaApi api;
    private final CoverageSweepEngine engine;
    private final OpenApiUrlFetcher openApiUrlFetcher;
    private final CandidateTableModel candidateTableModel = new CandidateTableModel();
    private final GlobalTrafficGovernor globalGovernor;

    private JButton loadButton;
    private JButton importButton;
    private JButton clearImportButton;
    private JButton startButton;
    private JButton stopButton;
    private JButton pauseButton;
    private JButton clearButton;
    private JButton previewProbesButton;
    private JButton viewCandidateButton;
    private JButton exportButton;
    private JButton authIdentifiersButton;
    private JButton applyOpenApiBaseUrlButton;
    private JButton configurationToggleButton;
    private JButton throttleButton;
    private JButton importMenuButton;
    private JButton excludeHostsButton;
    private JPanel configurationActionsRow;
    private JComboBox<String> modeComboBox;
    private JComboBox<String> payloadSetComboBox;
    private CoverageSweepFamilyControl payloadFamilyControl;
    private JCheckBox includeUnsafeMethodsCheckBox;
    private JCheckBox excludeStaticAssetsCheckBox;
    private JCheckBox verifyUnauthenticatedAccessCheckBox;
    private JCheckBox browserUserAgentCheckBox;
    private HostPortsControl hostPortsControl;
    private JCheckBox dedupeImportedEndpointsCheckBox;
    private RequestHeadersControl requestHeadersControl;
    private long userAgentRandomizationSeed =
        java.util.concurrent.ThreadLocalRandom.current().nextLong();
    private boolean configurationControlsEnabled = true;
    private ThrottleSettingsControl throttleControl;
    private JCheckBox status401CheckBox;
    private JCheckBox status403CheckBox;
    private JCheckBox status3xxCheckBox;
    private JCheckBox status4xxCheckBox;
    private JTextField openApiBaseUrlField;
    private JLabel openApiBaseUrlLabel;
    private JLabel statusLabel;
    private JLabel estimateLabel;
    private JLabel completedHostsLabel;
    private JLabel pullResponsesLabel;
    private JPanel configurationPanel;
    private JTable candidateTable;
    private JScrollPane candidatesScrollPane;
    private JSplitPane centerSplitPane;
    private SessionResultsWorkspace resultsWorkspace;
    private volatile boolean stopRequested = false;
    private boolean retryExecutionControlsActive;
    private List<CoverageSweepCandidate> cachedHistoryCandidates = List.of();
    private CoverageSweepPreview cachedHistoryPreview;
    private Set<String> discoveredAuthHeaders = Set.of();
    private Set<String> discoveredCookieNames = Set.of();
    private Set<String> selectedAuthHeaders = new LinkedHashSet<>(Set.of("Authorization"));
    private Set<String> selectedCookieNames = new LinkedHashSet<>();
    private final Map<HttpRequest, HttpResponse> importedControlResponses = new IdentityHashMap<>();
    private volatile SwingWorker<CoverageSweepPreview, Void> candidateLoadWorker;
    private volatile SwingWorker<List<CoverageSweepCandidate>, Void> sweepPreparationWorker;
    private volatile SwingWorker<RemoteOpenApiImport, Void> remoteImportWorker;
    private volatile SwingWorker<List<CoverageSweepProbe>, Void> probePreviewWorker;
    private ImportedOpenApiDocument importedOpenApiDocument;
    private boolean authDefaultsInitialized;
    private CoverageSweepPayloadSet activePayloadSet = CoverageSweepPayloadSet.HIGH_SIGNAL;
    private volatile boolean shuttingDown;
    private volatile boolean hasStarted;

    public CoverageSweepPanel(MontoyaApi api) {
        this(api, new GlobalTrafficGovernor());
    }

    public CoverageSweepPanel(MontoyaApi api, GlobalTrafficGovernor globalGovernor) {
        this(api, new CoverageSweepEngine(api, globalGovernor), OpenApiUrlFetcher.burp(api), globalGovernor);
    }

    CoverageSweepPanel(MontoyaApi api, CoverageSweepEngine engine) {
        this(api, engine, OpenApiUrlFetcher.burp(api), new GlobalTrafficGovernor());
    }

    CoverageSweepPanel(MontoyaApi api, CoverageSweepEngine engine, OpenApiUrlFetcher openApiUrlFetcher) {
        this(api, engine, openApiUrlFetcher, new GlobalTrafficGovernor());
    }

    CoverageSweepPanel(MontoyaApi api, CoverageSweepEngine engine, OpenApiUrlFetcher openApiUrlFetcher,
                       GlobalTrafficGovernor globalGovernor) {
        super(new BorderLayout());
        this.api = api;
        this.engine = engine;
        this.globalGovernor = globalGovernor == null ? new GlobalTrafficGovernor() : globalGovernor;
        this.openApiUrlFetcher = openApiUrlFetcher == null ? OpenApiUrlFetcher.burp(api) : openApiUrlFetcher;
        initializeUi();
    }

    public void cleanup() {
        shuttingDown = true;
        SwingWorker<CoverageSweepPreview, Void> worker = candidateLoadWorker;
        candidateLoadWorker = null;
        if (worker != null) {
            worker.cancel(true);
        }
        SwingWorker<RemoteOpenApiImport, Void> importWorker = remoteImportWorker;
        remoteImportWorker = null;
        if (importWorker != null) {
            importWorker.cancel(true);
        }
        SwingWorker<List<CoverageSweepProbe>, Void> previewWorker = probePreviewWorker;
        probePreviewWorker = null;
        if (previewWorker != null) {
            previewWorker.cancel(true);
        }
        SwingWorker<List<CoverageSweepCandidate>, Void> preparationWorker = sweepPreparationWorker;
        sweepPreparationWorker = null;
        if (preparationWorker != null) {
            preparationWorker.cancel(true);
        }
        engine.cleanup();
        if (resultsWorkspace != null) {
            resultsWorkspace.cleanup();
        }
    }

    @Override
    public String activityId() {
        return "coverage-sweep";
    }

    @Override
    public ActivitySnapshot activitySnapshot() {
        ActivityState state;
        if (shuttingDown) state = ActivityState.DISPOSED;
        else if (resultsWorkspace.isRetryRunning()) {
            state = resultsWorkspace.isRetryPaused() ? ActivityState.PAUSED : ActivityState.RETRYING;
        } else if (sweepPreparationWorker != null) state = ActivityState.PREPARING;
        else if (engine.isRunning()) state = engine.isPaused() ? ActivityState.PAUSED : ActivityState.RUNNING;
        else if (stopRequested || engine.phase() == CoverageSweepEngine.SweepPhase.STOPPED) {
            state = ActivityState.STOPPED;
        } else if (hasStarted || engine.phase() == CoverageSweepEngine.SweepPhase.COMPLETE) {
            state = ActivityState.COMPLETED;
        } else state = ActivityState.IDLE;

        int completed = engine.completedMainRequestCount();
        int planned = engine.plannedMainRequestCount();
        String progress = planned > 0 ? completed + " / " + planned + " main requests"
            : resultsWorkspace.allResultsCount() + " results";
        return new ActivitySnapshot(activityId(), "Sweep", "Coverage Sweep", state,
            progress, totalHttpRequestsSent());
    }

    @Override
    public void pauseActivity() {
        ActivitySnapshot snapshot = activitySnapshot();
        if (snapshot.active() && !snapshot.paused()) togglePause();
    }

    @Override
    public void resumeActivity() {
        if (activitySnapshot().paused()) togglePause();
    }

    @Override
    public void stopActivity() {
        if (activitySnapshot().active()) stopSweep();
    }

    private void initializeUi() {
        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildCenterPanel(), BorderLayout.CENTER);
    }

    private JPanel buildTopPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));
        JPanel modeRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel modeActionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        configurationActionsRow = modeActionsRow;
        JPanel modeOptionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel methodOptionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel executionRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel resultActionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        configurationPanel = new JPanel();
        configurationPanel.setLayout(new BoxLayout(configurationPanel, BoxLayout.Y_AXIS));

        modeComboBox = new JComboBox<>(new String[]{
            "Blocked responses",
            "Authenticated traffic",
            "Import targets"
        });
        modeComboBox.addActionListener(e -> handleModeChange());

        status401CheckBox = new JCheckBox("401", true);
        status403CheckBox = new JCheckBox("403", true);
        status3xxCheckBox = new JCheckBox("3xx", false);
        status4xxCheckBox = new JCheckBox("4xx", false);
        status401CheckBox.addActionListener(e -> updateEstimate());
        status403CheckBox.addActionListener(e -> updateEstimate());
        status3xxCheckBox.addActionListener(e -> updateEstimate());
        status4xxCheckBox.addActionListener(e -> updateEstimate());

        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        payloadSetComboBox = new JComboBox<>(new String[]{"High signal", "All payloads"});
        payloadSetComboBox.setToolTipText(
            "High signal uses the curated Sweep set; All payloads runs every Bypass attack family.");
        payloadSetComboBox.addActionListener(e -> updateEstimate());
        hostPortsControl = new HostPortsControl();
        hostPortsControl.setOnChange(this::updateEstimate);
        payloadFamilyControl = new CoverageSweepFamilyControl(
            this, this::currentPayloadSet, this::updateEstimate, hostPortsControl);
        throttleControl = new ThrottleSettingsControl(ThrottleDefaults.forCoverageSweep(defaults));
        requestHeadersControl = new RequestHeadersControl(this);
        dedupeImportedEndpointsCheckBox = new JCheckBox("Dedupe endpoints", false);
        dedupeImportedEndpointsCheckBox.setToolTipText(
            "Collapse imported targets with the same method, path shape, query names, and content type.");
        openApiBaseUrlField = new JTextField("", 20);
        openApiBaseUrlField.setToolTipText("Optional absolute base URL; overrides servers declared by an OpenAPI spec.");
        openApiBaseUrlField.addActionListener(e -> applyOpenApiBaseUrl());
        openApiBaseUrlLabel = new JLabel("OpenAPI base URL:");
        applyOpenApiBaseUrlButton = new JButton("Apply");
        applyOpenApiBaseUrlButton.setToolTipText(
            "Rebuild the imported OpenAPI targets using this base URL without importing the specification again.");
        applyOpenApiBaseUrlButton.addActionListener(e -> applyOpenApiBaseUrl());

        modeRow.add(new JLabel("Mode:"));
        modeRow.add(modeComboBox);
        configurationToggleButton = new JButton("Hide config");
        configurationToggleButton.setToolTipText("Show or hide sweep configuration options to make more room for results.");
        configurationToggleButton.addActionListener(e -> toggleConfigurationPanel());
        modeRow.add(configurationToggleButton);
        pullResponsesLabel = new JLabel("Pull responses:");
        modeOptionsRow.add(pullResponsesLabel);
        modeOptionsRow.add(status401CheckBox);
        modeOptionsRow.add(status403CheckBox);
        modeOptionsRow.add(status3xxCheckBox);
        modeOptionsRow.add(status4xxCheckBox);

        includeUnsafeMethodsCheckBox = new JCheckBox("Include state-changing methods", false);
        includeUnsafeMethodsCheckBox.setToolTipText(
            "Include POST, PUT, PATCH, DELETE, and other state-changing methods in the sweep selection.");
        includeUnsafeMethodsCheckBox.addActionListener(e -> handleUnsafeMethodsSelectionChange());
        excludeStaticAssetsCheckBox = new JCheckBox("Exclude static assets", true);
        excludeStaticAssetsCheckBox.setToolTipText(
            "Skip image, JavaScript, CSS, and WOFF responses when loading authenticated Proxy history.");
        verifyUnauthenticatedAccessCheckBox = new JCheckBox("Verify unauthenticated access", true);
        verifyUnauthenticatedAccessCheckBox.setToolTipText(
            "Replay each authenticated candidate without credentials and mark successful 2xx responses as LIKELY PUBLIC.");
        authIdentifiersButton = new JButton("Auth Identifiers...");
        authIdentifiersButton.addActionListener(e -> openAuthIdentifiersDialog());

        browserUserAgentCheckBox = new JCheckBox("Browser User-Agent", true);
        browserUserAgentCheckBox.setToolTipText(
            "Send every probe with a current desktop Chrome User-Agent (unless you set one yourself in Request Headers).");
        requestHeadersControl.setOnChange(this::updateBrowserUserAgentControl);
        updateBrowserUserAgentControl();
        executionRow.add(new JLabel("Payload set:"));
        executionRow.add(payloadSetComboBox);
        executionRow.add(payloadFamilyControl.button());
        throttleButton = throttleControl.button();
        executionRow.add(throttleButton);
        methodOptionsRow.add(includeUnsafeMethodsCheckBox);
        methodOptionsRow.add(browserUserAgentCheckBox);
        modeOptionsRow.add(excludeStaticAssetsCheckBox);
        modeOptionsRow.add(verifyUnauthenticatedAccessCheckBox);
        modeOptionsRow.add(openApiBaseUrlLabel);
        modeOptionsRow.add(openApiBaseUrlField);
        modeOptionsRow.add(applyOpenApiBaseUrlButton);


        loadButton = new JButton("Load from Proxy History");
        loadButton.addActionListener(e -> loadCandidates());
        importButton = new JButton("Import Targets");
        importButton.addActionListener(e -> importTargetsWithChooser());
        clearImportButton = new JButton("Clear Import");
        clearImportButton.addActionListener(e -> clearImport());
        startButton = new JButton("Start Sweep");
        startButton.setEnabled(false);
        startButton.addActionListener(e -> startSweep());
        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopSweep());
        pauseButton = new JButton("Pause");
        pauseButton.setEnabled(false);
        pauseButton.addActionListener(e -> togglePause());
        previewProbesButton = new JButton("Preview Probes");
        previewProbesButton.setEnabled(false);
        previewProbesButton.addActionListener(e -> openProbePreview());
        viewCandidateButton = new JButton("View");
        viewCandidateButton.setEnabled(false);
        viewCandidateButton.addActionListener(e -> openCandidateView());
        clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());
        exportButton = new JButton("Export...");
        exportButton.setEnabled(false);
        exportButton.setToolTipText("Export results, completed hosts, or deferred retry data.");
        exportButton.addActionListener(e -> openExportDialog());
        importMenuButton = new JButton("Import...");
        importMenuButton.setToolTipText("Import targets or an exact retry-package JSON file.");
        importMenuButton.addActionListener(e -> openImportDialog());
        excludeHostsButton = new JButton("Exclude...");
        excludeHostsButton.setToolTipText("Choose unique hosts to exclude from the current sweep candidates.");
        excludeHostsButton.addActionListener(e -> openExcludeHostsDialog());
        modeActionsRow.add(loadButton);
        modeActionsRow.add(clearImportButton);
        modeActionsRow.add(importMenuButton);
        modeActionsRow.add(exportButton);
        modeActionsRow.add(excludeHostsButton);
        modeActionsRow.add(viewCandidateButton);
        modeActionsRow.add(previewProbesButton);
        modeActionsRow.add(requestHeadersControl.button());
        modeActionsRow.add(clearButton);
        modeActionsRow.add(authIdentifiersButton);
        resultActionsRow.add(startButton);
        resultActionsRow.add(stopButton);
        resultActionsRow.add(pauseButton);

        controls.add(modeRow);
        controls.add(modeActionsRow);
        configurationPanel.add(modeOptionsRow);
        configurationPanel.add(methodOptionsRow);
        configurationPanel.add(executionRow);
        controls.add(configurationPanel);
        controls.add(resultActionsRow);

        statusLabel = new JLabel("Load in-scope Proxy history responses to preview sweep candidates.");
        estimateLabel = new JLabel("No candidates loaded.");
        completedHostsLabel = new JLabel("Completed hosts: 0 / 0");

        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusRow.add(statusLabel);
        statusRow.add(estimateLabel);
        JPanel labels = new JPanel();
        labels.setLayout(new BoxLayout(labels, BoxLayout.Y_AXIS));
        labels.add(statusRow);
        JPanel hostStatusRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hostStatusRow.add(completedHostsLabel);
        labels.add(hostStatusRow);

        panel.add(controls, BorderLayout.NORTH);
        panel.add(labels, BorderLayout.CENTER);
        updateModeControls();
        return panel;
    }

    private void showCandidatePopupIfNeeded(java.awt.event.MouseEvent e) {
        if (!e.isPopupTrigger()) {
            return;
        }
        int[] selectedViewRows = candidateTable.getSelectedRows();
        if (selectedViewRows.length == 0) {
            int viewRow = candidateTable.rowAtPoint(e.getPoint());
            if (viewRow < 0) return;
            candidateTable.setRowSelectionInterval(viewRow, viewRow);
            selectedViewRows = new int[]{viewRow};
        }
        int count = selectedViewRows.length;
        String label = count == 1 ? "1 row" : count + " rows";

        JPopupMenu popup = new JPopupMenu();
        int[] viewRows = selectedViewRows;

        JMenuItem enableItem = new JMenuItem("Enable " + label);
        enableItem.addActionListener(a -> setCandidateSelection(viewRows, true));
        popup.add(enableItem);

        JMenuItem disableItem = new JMenuItem("Disable " + label);
        disableItem.addActionListener(a -> setCandidateSelection(viewRows, false));
        popup.add(disableItem);

        popup.show(candidateTable, e.getX(), e.getY());
    }

    private void setCandidateSelection(int[] viewRows, boolean selected) {
        for (int viewRow : viewRows) {
            int modelRow = candidateTable.convertRowIndexToModel(viewRow);
            candidateTableModel.setSelectedAt(modelRow, selected);
        }
        if (viewRows.length > 0) {
            candidateTableModel.fireTableDataChanged();
        }
    }

    private void exportRetryQueueWordlist(List<AttackResult> queued) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Deferred Retry Wordlist");
        chooser.setSelectedFile(new java.io.File("bypassfuzzer-retry-queue.txt"));
        chooser.setFileFilter(new FileNameExtensionFilter("Wordlists (*.txt)", "txt"));
        int result = chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }
        exportRetryQueueWordlist(queued, chooser.getSelectedFile().toPath());
    }

    boolean exportRetryQueueWordlist(List<AttackResult> queued, Path path) {
        Set<String> payloads = new LinkedHashSet<>();
        if (queued != null) {
            for (AttackResult result : queued) {
                if (result != null && result.getPayload() != null && !result.getPayload().isBlank()) {
                    payloads.add(result.getPayload());
                }
            }
        }
        try {
            Files.write(path, payloads, StandardCharsets.UTF_8);
            statusLabel.setText("Exported " + payloads.size() + " unique retry payload(s) to " + path + ".");
            return true;
        } catch (Exception e) {
            statusLabel.setText("Unable to export retry wordlist: " + e.getMessage());
            try {
                JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Unable to export retry wordlist:\n" + e.getMessage(),
                    "Export Failed",
                    JOptionPane.ERROR_MESSAGE
                );
            } catch (Exception ignored) {
                // Headless tests or Burp shutdown can make dialogs unavailable.
            }
            return false;
        }
    }

    private void exportRetryQueueJson() {
        exportRetryQueueJson(resultsWorkspace.throttledRetrySnapshot());
    }

    private void exportRetryQueueJson(List<AttackResult> queued) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Deferred Retry JSON");
        chooser.setSelectedFile(new java.io.File("bypassfuzzer-retry-queue.json"));
        chooser.setFileFilter(new FileNameExtensionFilter("JSON retry packages (*.json)", "json"));
        int result = chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }
        try {
            List<RetryPackageEntry> entries = queued.stream()
                .filter(resultItem -> resultItem != null && resultItem.getRequest() != null)
                .map(this::toRetryPackageEntry)
                .toList();
            RetryPackage packageData = new RetryPackage("1", "bypassfuzzer-retry-queue", entries);
            Files.writeString(chooser.getSelectedFile().toPath(), new Gson().toJson(packageData),
                StandardCharsets.UTF_8);
            statusLabel.setText("Exported " + entries.size() + " exact retry request(s) to "
                + chooser.getSelectedFile() + ".");
        } catch (Exception e) {
            showRetryPackageError("Unable to export retry JSON: " + e.getMessage());
        }
    }

    private RetryPackageEntry toRetryPackageEntry(AttackResult result) {
        return new RetryPackageEntry(
            result.getTargetLabel(), result.getPayload(), result.getPayloadFamily(),
            result.getPayloadEncoding(), result.getThrottleRetryAttempt(),
            result.getRequest().toString(), result.getRequest().url(), result.getRequest().method(),
            retryHttpMode(result.getRequest()), result.getPayload()
        );
    }

    private String retryHttpMode(burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            String version = request.httpVersion();
            if (version != null && version.contains("2")) {
                return "HTTP_2";
            }
            if (version != null && version.contains("1")) {
                return "HTTP_1";
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    private void showRetryPackageError(String message) {
        statusLabel.setText(message);
        try {
            JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(), message,
                "Retry Package Error", JOptionPane.ERROR_MESSAGE);
        } catch (Exception ignored) {
            // Headless tests or Burp shutdown can make dialogs unavailable.
        }
    }

    private void openExportDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(owner, "Export Sweep Data", Dialog.ModalityType.MODELESS);
        JPanel content = new JPanel();
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(new JLabel("Choose what to export:"));

        JButton results = new JButton("Visible results (TSV)");
        results.setEnabled(resultsWorkspace.shownResultsCount() > 0);
        results.addActionListener(e -> {
            dialog.dispose();
            exportResultsWithChooser();
        });
        JButton hosts = new JButton("Completed hosts (wordlist)");
        hosts.setEnabled(engine.completedHostCount() > 0);
        hosts.addActionListener(e -> {
            dialog.dispose();
            exportCompletedHosts();
        });
        JButton retryWordlist = new JButton("Deferred retry payloads (wordlist)");
        retryWordlist.setEnabled(!resultsWorkspace.throttledRetrySnapshot().isEmpty());
        retryWordlist.addActionListener(e -> {
            dialog.dispose();
            exportRetryQueueWordlist(resultsWorkspace.throttledRetrySnapshot());
        });
        content.add(results);
        content.add(hosts);
        content.add(retryWordlist);
        JButton close = new JButton("Close");
        close.addActionListener(e -> dialog.dispose());
        JPanel closeRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        closeRow.add(close);
        content.add(closeRow);
        dialog.setContentPane(content);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private void openImportDialog() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dialog = new JDialog(owner, "Import Sweep Data", Dialog.ModalityType.MODELESS);
        JPanel content = new JPanel();
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(new JLabel("Choose what to import:"));

        JButton targetFile = new JButton("Import file");
        targetFile.setToolTipText("Import a newline-delimited target URL file or retry-queue JSON package.");
        targetFile.addActionListener(e -> {
            dialog.dispose();
            importTargetFile();
        });
        JButton openApi = new JButton("Import API specification");
        openApi.setToolTipText("Choose a local OpenAPI/Postman file or provide an OpenAPI specification URL.");
        openApi.addActionListener(e -> {
            dialog.dispose();
            openOpenApiImportDialog();
        });
        content.add(targetFile);
        content.add(openApi);
        JButton close = new JButton("Close");
        close.addActionListener(e -> dialog.dispose());
        JPanel closeRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        closeRow.add(close);
        content.add(closeRow);
        dialog.setContentPane(content);
        dialog.pack();
        dialog.setLocationRelativeTo(owner);
        dialog.setVisible(true);
    }

    private void exportCompletedHosts() {
        List<String> hosts = engine.completedHostSnapshot();
        if (hosts.isEmpty()) {
            statusLabel.setText("No completed sweep hosts are available to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Completed Host Wordlist");
        chooser.setSelectedFile(new java.io.File("bypassfuzzer-completed-hosts.txt"));
        chooser.setFileFilter(new FileNameExtensionFilter("Host wordlists (*.txt)", "txt"));
        if (chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame()) != JFileChooser.APPROVE_OPTION
            || chooser.getSelectedFile() == null) {
            return;
        }
        try {
            Files.write(chooser.getSelectedFile().toPath(), hosts, StandardCharsets.UTF_8);
            statusLabel.setText("Exported " + hosts.size() + " completed host(s) to "
                + chooser.getSelectedFile() + ".");
        } catch (Exception e) {
            showRetryPackageError("Unable to export completed hosts: " + e.getMessage());
        }
    }

    private void openExcludeHostsDialog() {
        Map<String, Integer> hostCounts = candidateTableModel.hostCounts();
        if (hostCounts.isEmpty()) {
            statusLabel.setText("No candidate hosts are available to exclude.");
            return;
        }
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(new JLabel("Select hosts to exclude from this sweep:"));
        List<JCheckBox> hostBoxes = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : hostCounts.entrySet()) {
            JCheckBox box = new JCheckBox(entry.getKey() + " (" + entry.getValue() + " request(s))");
            box.putClientProperty("host", entry.getKey());
            hostBoxes.add(box);
            content.add(box);
        }
        JScrollPane scroll = new JScrollPane(content);
        scroll.setPreferredSize(new Dimension(520, 360));
        int choice = JOptionPane.showConfirmDialog(this, scroll, "Exclude Hosts",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) {
            return;
        }
        Set<String> excluded = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (JCheckBox box : hostBoxes) {
            if (box.isSelected()) {
                excluded.add((String) box.getClientProperty("host"));
            }
        }
        int removed = candidateTableModel.excludeHosts(excluded);
        updateEstimate();
        updatePreviewButton();
        statusLabel.setText("Excluded " + excluded.size() + " host(s); removed " + removed + " request(s).");
    }

    private record RetryPackage(String version, String type, List<RetryPackageEntry> entries) {
    }

    private record RetryPackageEntry(String targetLabel, String payload, String payloadFamily,
                                     String payloadEncoding, int retryAttempt, String requestRaw,
                                     String url, String method, String httpMode, String payloadLabel) {
    }

    private void toggleConfigurationPanel() {
        boolean expanded = configurationPanel.isVisible();
        configurationPanel.setVisible(!expanded);
        configurationActionsRow.setVisible(!expanded);
        candidatesScrollPane.setVisible(!expanded);
        if (expanded) {
            centerSplitPane.setDividerSize(0);
        } else {
            centerSplitPane.setDividerSize(javax.swing.UIManager.getInt("SplitPane.dividerSize"));
            centerSplitPane.setDividerLocation(220);
        }
        configurationToggleButton.setText(expanded ? "Show config" : "Hide config");
        revalidate();
        repaint();
    }

    private JSplitPane buildCenterPanel() {
        candidateTable = new JTable(candidateTableModel);
        candidateTable.setAutoCreateRowSorter(true);
        candidateTableModel.addTableModelListener(e -> {
            updateEstimate();
            updatePreviewButton();
            if (!engine.isRunning() && startButton != null) {
                startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
            }
        });
        candidateTable.getColumnModel().getColumn(0).setMaxWidth(55);
        candidateTable.getColumnModel().getColumn(1).setMaxWidth(72);
        candidateTable.getColumnModel().getColumn(4).setMaxWidth(70);
        candidateTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updatePreviewButton();
            }
        });
        candidateTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                showCandidatePopupIfNeeded(e);
            }
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                showCandidatePopupIfNeeded(e);
            }
        });
        candidatesScrollPane = new JScrollPane(candidateTable);
        candidatesScrollPane.setBorder(BorderFactory.createTitledBorder("Candidates"));

        resultsWorkspace = new SessionResultsWorkspace(
            api,
            message -> api.logging().logToError(message),
            workspace -> {
                updateExportButton();
                api.logging().logToOutput(
                    "Coverage sweep filters applied: showing " + workspace.shownResultsCount() + " of " + workspace.allResultsCount() + " results"
                );
            },
            SessionResultsPanel.ViewerLayout.BELOW_TABLE,
            SessionResultsPanel.TableLayout.COVERAGE_SWEEP,
            false,
            globalGovernor
        );
        resultsWorkspace.setResultsChangedListener(this::handleResultBatch);
        resultsWorkspace.setAuthVerificationTabsVisible(false);
        resultsWorkspace.setRetryQueueExportAction(() ->
            exportRetryQueueJson(resultsWorkspace.throttledRetrySnapshot()));
        resultsWorkspace.setThrottleRetryQueueChangedListener(() -> {
            updateRetryQueueButton();
            updateExecutionControlsForRetry();
        });

        centerSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, candidatesScrollPane, resultsWorkspace.component());
        centerSplitPane.setResizeWeight(0.25);
        SwingUtilities.invokeLater(() -> centerSplitPane.setDividerLocation(220));
        return centerSplitPane;
    }

    private void loadCandidates() {
        CoverageSweepOptions currentOptions = currentOptions();
        if (currentOptions.mode() == CoverageSweepMode.BLOCKED_RESPONSES && currentOptions.statuses().isEmpty()) {
            statusLabel.setText("Select at least one response status group before loading Proxy history.");
            startButton.setEnabled(false);
            return;
        }

        setControlsForLoading();
        if (!SwingUtilities.isEventDispatchThread()) {
            loadCandidatesSynchronously(currentOptions);
            return;
        }

        candidateLoadWorker = new SwingWorker<>() {
            @Override
            protected CoverageSweepPreview doInBackground() {
                return engine.collectPreview(currentOptions);
            }

            @Override
            protected void done() {
                if (candidateLoadWorker != this) {
                    return;
                }
                try {
                    applyLoadedCandidates(get(), currentOptions);
                } catch (CancellationException e) {
                    statusLabel.setText("Proxy history loading cancelled.");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    handleCandidateLoadFailure(e);
                } catch (ExecutionException e) {
                    handleCandidateLoadFailure(e.getCause() == null ? e : e.getCause());
                } finally {
                    candidateLoadWorker = null;
                    finishCandidateLoading();
                }
            }
        };
        candidateLoadWorker.execute();
    }

    private void loadCandidatesSynchronously(CoverageSweepOptions options) {
        try {
            applyLoadedCandidates(engine.collectPreview(options), options);
        } catch (Exception e) {
            handleCandidateLoadFailure(e);
        } finally {
            finishCandidateLoading();
        }
    }

    private void applyLoadedCandidates(CoverageSweepPreview preview, CoverageSweepOptions options) {
        cachedHistoryCandidates = preview.candidates();
        cachedHistoryPreview = preview;
        discoveredAuthHeaders = preview.discoveredHeaderNames();
        discoveredCookieNames = preview.discoveredCookieNames();
        if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            if (!authDefaultsInitialized) {
                selectObviousIdentifiers();
                authDefaultsInitialized = true;
            }
            refilterAuthenticatedCandidates();
        } else {
            setCandidateRows(preview.candidates());
        }
        startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
        updatePreviewButton();
        statusLabel.setText("Found " + preview.blockedHistoryCount()
            + " matching history items; " + preview.dedupedEndpointCount()
            + " deduped endpoints; showing " + preview.candidates().size() + ".");
        if (options.mode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            updateAuthenticatedStatus(preview);
        }
        updateEstimate();
    }

    private void handleCandidateLoadFailure(Throwable error) {
        String message = error == null || error.getMessage() == null
            ? "unknown error" : error.getMessage();
        statusLabel.setText("Unable to load Proxy history: " + message);
        startButton.setEnabled(false);
        setCandidateActionButtonsEnabled(false);
    }

    private void finishCandidateLoading() {
        loadButton.setEnabled(true);
        importButton.setEnabled(true);
        setStatusControlsEnabled(true);
        candidateTableModel.setSelectionEditingEnabled(true);
        updatePreviewButton();
    }

    private boolean requireImportedMode() {
        if (currentMode() != CoverageSweepMode.IMPORTED_TARGETS) {
            statusLabel.setText("Select Import targets mode before importing targets or API specifications.");
            return false;
        }
        return true;
    }

    private void importTargetFile() {
        if (!requireImportedMode()) {
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Target File");
        chooser.setFileFilter(targetImportFileFilter());
        if (chooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame()) == JFileChooser.APPROVE_OPTION
            && chooser.getSelectedFile() != null) {
            importTargetsFromFile(chooser.getSelectedFile().toPath());
        }
    }

    private void openOpenApiImportDialog() {
        if (!requireImportedMode()) {
            return;
        }
        JPanel choicesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        choicesPanel.add(new JLabel("OpenAPI source:"));
        choicesPanel.add(dedupeImportedEndpointsCheckBox);
        Object[] choices = {"Local file", "URL", "Cancel"};
        int sourceChoice = JOptionPane.showOptionDialog(this, choicesPanel, "Import OpenAPI Specification",
            JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, choices, choices[0]);
        if (sourceChoice == 0) {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Import OpenAPI Specification");
            chooser.setFileFilter(new FileNameExtensionFilter(
                "OpenAPI and Postman collections (*.json, *.yaml, *.yml)", "json", "yaml", "yml"));
            if (chooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame()) == JFileChooser.APPROVE_OPTION
                && chooser.getSelectedFile() != null) {
                importTargetsFromFile(chooser.getSelectedFile().toPath());
            }
            return;
        }
        if (sourceChoice != 1) {
            return;
        }
        JTextField urlField = new JTextField(48);
        JComboBox<String> httpModeComboBox = new JComboBox<>(new String[]{"HTTP/1.1", "HTTP/2"});
        JPanel remoteImportPanel = new JPanel();
        remoteImportPanel.setLayout(new BoxLayout(remoteImportPanel, BoxLayout.Y_AXIS));
        remoteImportPanel.add(new JLabel("OpenAPI JSON or YAML URL:"));
        remoteImportPanel.add(urlField);
        JPanel protocolRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 6));
        protocolRow.add(new JLabel("HTTP version: "));
        protocolRow.add(httpModeComboBox);
        remoteImportPanel.add(protocolRow);
        int result = JOptionPane.showConfirmDialog(this, remoteImportPanel,
            "Import OpenAPI via URL", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION && !urlField.getText().isBlank()) {
            HttpMode httpMode = httpModeComboBox.getSelectedIndex() == 1 ? HttpMode.HTTP_2 : HttpMode.HTTP_1;
            importTargetsFromUrl(urlField.getText(), httpMode);
        }
    }

    private void importTargetsWithChooser() {
        if (currentMode() != CoverageSweepMode.IMPORTED_TARGETS) {
            statusLabel.setText("Select Import targets mode to load a URL list.");
            return;
        }

        JPanel importChoices = new JPanel();
        importChoices.setLayout(new BoxLayout(importChoices, BoxLayout.Y_AXIS));
        importChoices.add(new JLabel("How would you like to import sweep targets?"));
        importChoices.add(dedupeImportedEndpointsCheckBox);
        Object[] choices = {"Select a file", "Import via URL", "Cancel"};
        int sourceChoice = JOptionPane.showOptionDialog(
            this,
            importChoices,
            "Import Targets",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.PLAIN_MESSAGE,
            null,
            choices,
            choices[0]
        );
        if (sourceChoice == 1) {
            JTextField urlField = new JTextField(48);
            JComboBox<String> httpModeComboBox = new JComboBox<>(new String[]{"HTTP/1.1", "HTTP/2"});
            JPanel remoteImportPanel = new JPanel();
            remoteImportPanel.setLayout(new BoxLayout(remoteImportPanel, BoxLayout.Y_AXIS));
            remoteImportPanel.add(new JLabel("OpenAPI JSON or YAML URL:"));
            remoteImportPanel.add(urlField);
            JPanel protocolRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 6));
            protocolRow.add(new JLabel("HTTP version: "));
            protocolRow.add(httpModeComboBox);
            remoteImportPanel.add(protocolRow);
            int result = JOptionPane.showConfirmDialog(
                this,
                remoteImportPanel,
                "Import OpenAPI via URL",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
            );
            if (result == JOptionPane.OK_OPTION && !urlField.getText().isBlank()) {
                HttpMode httpMode = httpModeComboBox.getSelectedIndex() == 1
                    ? HttpMode.HTTP_2 : HttpMode.HTTP_1;
                importTargetsFromUrl(urlField.getText(), httpMode);
            }
            return;
        }
        if (sourceChoice != 0) {
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Sweep Targets");
        chooser.setFileFilter(new FileNameExtensionFilter(
            "Targets, retry JSON, OpenAPI specs, and Postman collections (*.txt, *.json, *.yaml, *.yml)",
            "txt", "json", "yaml", "yml"));
        int result = chooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame());
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }

        importTargetsFromFile(chooser.getSelectedFile().toPath());
    }

    boolean importTargetsFromUrl(String rawUrl) {
        return importTargetsFromUrl(rawUrl, HttpMode.HTTP_1);
    }

    boolean importTargetsFromUrl(String rawUrl, HttpMode httpMode) {
        OpenApiUrlFetcher.ParsedUrl target;
        try {
            target = OpenApiUrlFetcher.parse(rawUrl);
        } catch (IllegalArgumentException e) {
            statusLabel.setText("Unable to import targets: " + e.getMessage());
            return false;
        }

        setControlsForLoading();
        statusLabel.setText("Downloading OpenAPI document from " + target.host() + "...");
        CoverageSweepOptions options = currentOptions();
        String baseUrl = openApiBaseUrlField.getText().trim();
        boolean dedupeEndpoints = dedupeImportedEndpointsCheckBox.isSelected();
        SwingWorker<RemoteOpenApiImport, Void> worker = new SwingWorker<>() {
            @Override
            protected RemoteOpenApiImport doInBackground() throws Exception {
                String fileName = remoteFileName(target.requestTarget());
                OpenApiUrlFetcher.FetchedDocument fetched = openApiUrlFetcher.fetchDocument(
                    target.rawUrl(), httpMode, options.requestHeaders());
                String source = fetched.source();
                CoverageSweepPreview preview = engine.collectPreviewFromOpenApi(
                    source, fileName, baseUrl, fetched.effectiveUrl(), options, dedupeEndpoints);
                return new RemoteOpenApiImport(preview,
                    new ImportedOpenApiDocument(source, fileName, fetched.effectiveUrl(), false));
            }

            @Override
            protected void done() {
                if (remoteImportWorker != this) {
                    return;
                }
                try {
                    RemoteOpenApiImport imported = get();
                    importedOpenApiDocument = imported.document();
                    applyImportedPreview(imported.preview(), true, dedupeEndpoints);
                } catch (CancellationException e) {
                    statusLabel.setText("OpenAPI URL import cancelled.");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    handleImportFailure(e);
                } catch (ExecutionException e) {
                    handleImportFailure(e.getCause() == null ? e : e.getCause());
                } catch (Exception e) {
                    handleImportFailure(e);
                } finally {
                    remoteImportWorker = null;
                    finishCandidateLoading();
                }
            }
        };
        remoteImportWorker = worker;
        worker.execute();
        return true;
    }

    boolean importTargetsFromFile(Path path) {
        setControlsForLoading();
        try {
            String source = Files.readString(path);
            RetryPackage retryPackage = parseRetryPackage(source);
            if (retryPackage != null) {
                List<String> retryUrls = retryPackage.entries().stream()
                    .filter(entry -> entry != null && entry.url() != null && !entry.url().isBlank())
                    .map(RetryPackageEntry::url)
                    .toList();
                if (retryUrls.isEmpty()) {
                    throw new IllegalArgumentException("Retry package contains no request URLs");
                }
                boolean dedupeEndpoints = dedupeImportedEndpointsCheckBox.isSelected();
                CoverageSweepPreview preview = engine.collectPreviewFromUrls(
                    retryUrls, currentOptions(), dedupeEndpoints);
                importedOpenApiDocument = null;
                applyImportedPreview(preview, false, dedupeEndpoints);
                statusLabel.setText("Imported " + retryUrls.size()
                    + " retry-package request(s) as Sweep candidates; "
                    + importedPreviewCounts(preview, dedupeEndpoints));
                return true;
            }
            boolean postman = PostmanCollectionParser.looksLikePostmanCollection(source);
            boolean openApi = !postman && isOpenApiSource(path, source);
            String fileName = path.getFileName().toString();
            CoverageSweepPreview preview = postman
                ? engine.collectPreviewFromPostman(source, openApiBaseUrlField.getText().trim(),
                    currentOptions(), dedupeImportedEndpointsCheckBox.isSelected())
                : openApi
                ? engine.collectPreviewFromOpenApi(source, fileName,
                    openApiBaseUrlField.getText().trim(), "", currentOptions(),
                    dedupeImportedEndpointsCheckBox.isSelected())
                : engine.collectPreviewFromUrls(Files.readAllLines(path), currentOptions(),
                    dedupeImportedEndpointsCheckBox.isSelected());
            importedOpenApiDocument = openApi || postman
                ? new ImportedOpenApiDocument(source, fileName, "", postman)
                : null;
            applyImportedPreview(preview, postman ? "Postman request" : openApi ? "OpenAPI operation" : "valid target URL",
                dedupeImportedEndpointsCheckBox.isSelected());
            return true;
        } catch (Exception e) {
            handleImportFailure(e);
            return false;
        } finally {
            finishCandidateLoading();
        }
    }

    private void applyOpenApiBaseUrl() {
        if (currentMode() != CoverageSweepMode.IMPORTED_TARGETS || engine.isRunning()) {
            return;
        }
        ImportedOpenApiDocument document = importedOpenApiDocument;
        if (document == null) {
            statusLabel.setText("Import an OpenAPI or Postman document before applying a base URL.");
            return;
        }

        String baseUrl = openApiBaseUrlField.getText().trim();
        setControlsForLoading();
        statusLabel.setText(baseUrl.isEmpty()
            ? "Restoring server URLs declared by the imported OpenAPI specification..."
            : "Applying OpenAPI base URL " + baseUrl + "...");
        try {
            CoverageSweepPreview preview = document.postman()
                ? engine.collectPreviewFromPostman(document.source(), baseUrl, currentOptions(),
                    dedupeImportedEndpointsCheckBox.isSelected())
                : document.sourceUrl().isBlank()
                ? engine.collectPreviewFromOpenApi(
                    document.source(), document.fileName(), baseUrl, "", currentOptions(),
                    dedupeImportedEndpointsCheckBox.isSelected())
                : engine.collectPreviewFromOpenApi(
                    document.source(), document.fileName(), baseUrl, document.sourceUrl(), currentOptions(),
                    dedupeImportedEndpointsCheckBox.isSelected());
            applyImportedPreview(preview, document.postman() ? "Postman request" : "OpenAPI operation",
                dedupeImportedEndpointsCheckBox.isSelected());
            statusLabel.setText((baseUrl.isEmpty()
                ? (document.postman() ? "Restored Postman request URLs; " : "Restored OpenAPI server URLs; ")
                : (document.postman() ? "Applied Postman base URL " : "Applied OpenAPI base URL ")
                    + baseUrl + "; ")
                + importedPreviewCounts(preview, dedupeImportedEndpointsCheckBox.isSelected()));
        } catch (Exception e) {
            String message = e.getMessage() == null ? "unknown error" : e.getMessage();
            statusLabel.setText("Unable to apply OpenAPI base URL: " + message);
            startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
            updatePreviewButton();
        } finally {
            finishCandidateLoading();
        }
    }

    private void applyImportedPreview(CoverageSweepPreview preview, boolean openApi,
                                      boolean dedupeEndpoints) {
        applyImportedPreview(preview, openApi ? "OpenAPI operation" : "valid target URL", dedupeEndpoints);
    }

    private void applyImportedPreview(CoverageSweepPreview preview, String itemLabel,
                                      boolean dedupeEndpoints) {
        setCandidateRows(preview.candidates());
        applyImportedMethodSelection();
        startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
        updatePreviewButton();
        statusLabel.setText("Imported " + preview.blockedHistoryCount()
            + " " + itemLabel + "(s); "
            + importedPreviewCounts(preview, dedupeEndpoints));
        updateEstimate();
    }

    private String importedPreviewCounts(CoverageSweepPreview preview, boolean dedupeEndpoints) {
        return preview.dedupedEndpointCount() + " unique endpoint shape(s); "
            + (dedupeEndpoints ? "dedupe on" : "dedupe off") + "; showing "
            + preview.candidates().size() + " row(s).";
    }

    private void handleImportFailure(Throwable error) {
        importedOpenApiDocument = null;
        setCandidateRows(List.of());
        String message = error == null || error.getMessage() == null ? "unknown error" : error.getMessage();
        statusLabel.setText("Unable to import targets: " + message);
        startButton.setEnabled(false);
        setCandidateActionButtonsEnabled(false);
    }

    private String remoteFileName(String requestTarget) {
        String path = requestTarget;
        int query = path == null ? -1 : path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }
        if (path == null || path.isBlank() || path.endsWith("/")) {
            return "openapi.json";
        }
        int separator = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        String name = path.substring(separator + 1);
        return name.isBlank() ? "openapi.json" : name;
    }

    private boolean isOpenApiSource(Path path, String source) {
        String name = path == null || path.getFileName() == null ? ""
            : path.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".json") || name.endsWith(".yaml") || name.endsWith(".yml")) return true;
        String trimmed = source == null ? "" : source.stripLeading();
        return trimmed.startsWith("openapi:") || trimmed.startsWith("swagger:")
            || (trimmed.startsWith("{") && (trimmed.contains("\"openapi\"") || trimmed.contains("\"swagger\"")));
    }

    private void startSweep() {
        if (resultsWorkspace.isRetryRunning() || sweepPreparationWorker != null) {
            statusLabel.setText("Wait for the throttled-request retry pass to finish.");
            return;
        }

        stopRequested = false;
        loadButton.setEnabled(false);
        importButton.setEnabled(false);
        setStatusControlsEnabled(false);
        candidateTableModel.setSelectionEditingEnabledSilently(false);
        previewProbesButton.setEnabled(false);
        viewCandidateButton.setEnabled(true);
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        candidateTable.setEnabled(true);
        statusLabel.setText("Preparing selected sweep candidates...");

        CoverageSweepOptions options = currentOptions();
        activePayloadSet = options.payloadSet();
        resultsWorkspace.configureThrottleRetries(options.throttleSettings());
        resultsWorkspace.setPrimaryRunActive(true);
        sweepPreparationWorker = new SwingWorker<>() {
            @Override
            protected List<CoverageSweepCandidate> doInBackground() {
                return candidateTableModel.selectedCandidates();
            }

            @Override
            protected void done() {
                if (sweepPreparationWorker != this) {
                    return;
                }
                sweepPreparationWorker = null;
                try {
                    List<CoverageSweepCandidate> selected = get();
                    if (selected.isEmpty()) {
                        resultsWorkspace.setPrimaryRunActive(false);
                        updateIdleUi("Select at least one candidate before starting.");
                        return;
                    }
                    viewCandidateButton.setEnabled(true);
                    statusLabel.setText("Coverage sweep in progress...");
                    updateRetryQueueButton();
                    if (!engine.start(selected, options, CoverageSweepPanel.this::addResult,
                        CoverageSweepPanel.this::handleCompletion)) {
                        resultsWorkspace.setPrimaryRunActive(false);
                        updateIdleUi("Unable to start coverage sweep.");
                    } else {
                        hasStarted = true;
                        pauseButton.setText("Pause");
                        pauseButton.setEnabled(true);
                    }
                    updateCompletedHostsLabel();
                } catch (CancellationException ignored) {
                    resultsWorkspace.setPrimaryRunActive(false);
                    updateIdleUi("Coverage sweep preparation cancelled.");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    resultsWorkspace.setPrimaryRunActive(false);
                    updateIdleUi("Coverage sweep preparation interrupted.");
                } catch (ExecutionException e) {
                    resultsWorkspace.setPrimaryRunActive(false);
                    updateIdleUi("Unable to prepare coverage sweep: "
                        + (e.getCause() == null ? e.getMessage() : e.getCause().getMessage()));
                }
            }
        };
        sweepPreparationWorker.execute();
    }

    private void stopSweep() {
        SwingWorker<List<CoverageSweepCandidate>, Void> preparationWorker = sweepPreparationWorker;
        if (preparationWorker != null) {
            stopRequested = true;
            sweepPreparationWorker = null;
            preparationWorker.cancel(true);
            resultsWorkspace.setPrimaryRunActive(false);
            updateIdleUi("Coverage sweep preparation stopped.");
            return;
        }
        if (resultsWorkspace.isRetryRunning()) {
            resultsWorkspace.stopThrottleRetry();
            stopButton.setEnabled(false);
            pauseButton.setEnabled(false);
            statusLabel.setText("Stopping throttle retry pass...");
            return;
        }
        stopRequested = true;
        stopButton.setEnabled(false);
        pauseButton.setEnabled(false);
        statusLabel.setText("Stopping coverage sweep...");
        engine.stop();
    }

    private void togglePause() {
        if (resultsWorkspace.isRetryRunning()) {
            if (resultsWorkspace.isRetryPaused()) {
                resultsWorkspace.resumeThrottleRetry();
                pauseButton.setText("Pause");
            } else {
                resultsWorkspace.pauseThrottleRetry();
                pauseButton.setText("Resume");
            }
            statusLabel.setText(resultsWorkspace.retryStatusText());
            return;
        }
        if (!engine.isRunning()) return;
        if (engine.isPaused()) {
            engine.resume();
            pauseButton.setText("Pause");
            statusLabel.setText(runningStatusText("Resumed. "));
        } else {
            engine.pause();
            pauseButton.setText("Resume");
            int inFlight = engine.inFlightRequestCount();
            statusLabel.setText(inFlight > 0
                ? "Paused. Waiting for " + inFlight + " already-sent request(s) to finish."
                : "Paused. No new requests will be sent.");
        }
    }

    FileNameExtensionFilter targetImportFileFilter() {
        return new FileNameExtensionFilter(
            "Target lists, retry packages, and Postman collections (*.txt, *.json)", "txt", "json");
    }

    private RetryPackage parseRetryPackage(String source) {
        if (source == null || source.isBlank() || !source.stripLeading().startsWith("{")) {
            return null;
        }
        try {
            RetryPackage retryPackage = new Gson().fromJson(source, RetryPackage.class);
            return retryPackage != null
                && "bypassfuzzer-retry-queue".equals(retryPackage.type())
                && retryPackage.entries() != null
                ? retryPackage : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private void clearResults() {
        resultsWorkspace.clear();
        updateExportButton();
        statusLabel.setText("Coverage sweep results cleared.");
    }

    private void addResult(AttackResult result) {
        resultsWorkspace.enqueueResult(result);
    }

    private void handleResultBatch(List<AttackResult> results) {
        for (AttackResult result : results) {
            if (result.getOriginalRequest() != null && result.getOriginalResponse() != null) {
                importedControlResponses.put(result.getOriginalRequest(), result.getOriginalResponse());
            }
        }
        updateExportButton();
        updateRetryQueueButton();
        updateCompletedHostsLabel();
        statusLabel.setText(runningStatusText(engine.isPaused() ? "Paused. " : ""));
    }

    private void handleCompletion() {
        resultsWorkspace.afterPendingResults(() -> {
            resultsWorkspace.setPrimaryRunActive(false);
            updateIdleUi((stopRequested ? "Stopped" : "Completed")
                + " (" + payloadSetLabel(activePayloadSet) + "): "
                + engine.completedMainRequestCount() + " / " + engine.plannedMainRequestCount()
                + " generated main request(s) completed; " + totalHttpRequestsSent()
                + " actual HTTP request(s) sent; " + resultsWorkspace.throttledRetryCount()
                + " remain in the retry queue"
                + (engine.quarantinedRetryRequestCount() > 0
                    ? " (" + engine.quarantinedRetryRequestCount() + " pattern-throttled)" : "")
                + ".");
            updateRetryQueueButton();
            updateCompletedHostsLabel();
            userAgentRandomizationSeed = java.util.concurrent.ThreadLocalRandom.current().nextLong();
        });
    }

    private void updateCompletedHostsLabel() {
        if (completedHostsLabel != null) {
            completedHostsLabel.setText("Completed hosts: " + engine.completedHostCount()
                + " / " + engine.totalHostCount());
        }
    }

    private void updateRetryQueueButton() {
        updateExportButton();
    }

    private String payloadSetLabel(CoverageSweepPayloadSet payloadSet) {
        return payloadSet == CoverageSweepPayloadSet.ALL_PAYLOADS ? "All payloads" : "High signal";
    }

    private void updateExecutionControlsForRetry() {
        if (startButton == null || stopButton == null || pauseButton == null) return;
        if (resultsWorkspace.isRetryRunning()) {
            retryExecutionControlsActive = true;
            startButton.setText("Retrying queue...");
            startButton.setEnabled(false);
            stopButton.setText("Stop Retry");
            stopButton.setEnabled(true);
            pauseButton.setText(resultsWorkspace.isRetryPaused() ? "Resume" : "Pause");
            pauseButton.setEnabled(true);
            statusLabel.setText(resultsWorkspace.retryStatusText());
            return;
        }
        if (!retryExecutionControlsActive) return;
        retryExecutionControlsActive = false;
        startButton.setText("Start Sweep");
        stopButton.setText("Stop");
        if (!engine.isRunning() && sweepPreparationWorker == null) {
            startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
            stopButton.setEnabled(false);
            pauseButton.setText("Pause");
            pauseButton.setEnabled(false);
            if (resultsWorkspace.retryStatusText() != null
                && !resultsWorkspace.retryStatusText().isBlank()) {
                statusLabel.setText(resultsWorkspace.retryStatusText());
            }
        }
    }

    private String runningStatusText(String prefix) {
        CoverageSweepEngine.SweepPhase phase = engine.phase();
        String paused = prefix == null ? "" : prefix;
        if (phase == CoverageSweepEngine.SweepPhase.PREPARING) {
            return paused + "Preparing exact Sweep probe plan...";
        }
        if (phase == CoverageSweepEngine.SweepPhase.AUTOMATIC_RETRIES) {
            return paused + "Automatic throttle retry phase: main sweep "
                + engine.completedMainRequestCount() + " / " + engine.plannedMainRequestCount()
                + " complete; " + engine.automaticRetryRequestCount() + " retry/control request(s) sent; "
                + resultsWorkspace.throttledRetryCount() + " unique request(s) currently queued"
                + (engine.quarantinedRetryRequestCount() > 0
                    ? "; " + engine.quarantinedRetryRequestCount() + " pattern-throttled" : "")
                + ".";
        }
        return paused + "Main sweep (" + payloadSetLabel(activePayloadSet) + "): "
            + engine.completedMainRequestCount() + " / " + engine.plannedMainRequestCount()
            + " generated request(s) completed; " + totalHttpRequestsSent()
            + " actual HTTP request(s) sent; " + resultsWorkspace.throttledRetryCount()
            + " unique request(s) currently queued.";
    }

    private int totalHttpRequestsSent() {
        long sent = (long) engine.sentRequestCount() + resultsWorkspace.retryRequestCount();
        return (int) Math.min(Integer.MAX_VALUE, sent);
    }

    private void setControlsForLoading() {
        loadButton.setEnabled(false);
        importButton.setEnabled(false);
        clearImportButton.setEnabled(false);
        setStatusControlsEnabled(false);
        setCandidateActionButtonsEnabled(false);
        candidateTableModel.setSelectionEditingEnabled(false);
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
        pauseButton.setText("Pause");
        pauseButton.setEnabled(false);
        statusLabel.setText("Loading Proxy history...");
    }

    private void updateIdleUi(String message) {
        statusLabel.setText(message);
        startButton.setText("Start Sweep");
        stopButton.setText("Stop");
        loadButton.setEnabled(true);
        importButton.setEnabled(true);
        clearImportButton.setEnabled(currentMode() == CoverageSweepMode.IMPORTED_TARGETS
            && candidateTableModel.getRowCount() > 0);
        setStatusControlsEnabled(true);
        startButton.setEnabled(!candidateTableModel.selectedCandidates().isEmpty());
        stopButton.setEnabled(false);
        pauseButton.setEnabled(false);
        candidateTable.setEnabled(true);
        candidateTableModel.setSelectionEditingEnabled(true);
        updateEstimate();
        updatePreviewButton();
    }

    private void updateEstimate() {
        int selected = candidateTableModel.selectedCandidates().size();
        CoverageSweepOptions options = currentOptions();
        if (options.payloadSet() == CoverageSweepPayloadSet.ALL_PAYLOADS) {
            int enabled = options.familySelection().bypassFamilies().size();
            estimateLabel.setText("Selected " + selected
                + " endpoint(s); " + enabled + "/"
                + com.bypassfuzzer.burp.core.attacks.AttackType.values().length
                + " Bypass payload families enabled per endpoint.");
            return;
        }
        int hostPortProbes = hostPortsControl != null
            && options.familySelection().highSignalFamilies().contains("Host Parsing")
            ? hostPortsControl.probeCount() : 0;
        int probesPerCandidate = options.maxProbesPerCandidate() + hostPortProbes;
        int estimate = selected * probesPerCandidate;
        int enabled = options.familySelection().highSignalFamilies().size();
        estimateLabel.setText("Selected " + selected + " endpoint(s); " + enabled + "/"
            + com.bypassfuzzer.burp.core.coverage.CoverageSweepFamilySelection.HIGH_SIGNAL_FAMILIES.size()
            + " High Signal families enabled; configuration ceiling " + estimate
            + " request(s). Exact generated count is calculated when the sweep starts.");
    }

    private record RemoteOpenApiImport(CoverageSweepPreview preview, ImportedOpenApiDocument document) {
    }

    private record ImportedOpenApiDocument(String source, String fileName, String sourceUrl, boolean postman) {
    }

    private CoverageSweepOptions currentOptions() {
        CoverageSweepOptions defaults = CoverageSweepOptions.defaults();
        return new CoverageSweepOptions(
            selectedStatuses(),
            defaults.inScopeOnly(),
            defaults.maxCandidates(),
            defaults.maxProbesPerCandidate(),
            throttleControl != null ? throttleControl.concurrency() : defaults.concurrency(),
            throttleControl != null ? throttleControl.perHostConcurrency() : defaults.perHostConcurrency(),
            throttleControl != null ? throttleControl.throttleStatusCodes() : defaults.throttleStatusCodes(),
            currentMode(),
            currentAuthSelection(),
            excludeStaticAssetsCheckBox == null || excludeStaticAssetsCheckBox.isSelected(),
            verifyUnauthenticatedAccessCheckBox != null && verifyUnauthenticatedAccessCheckBox.isSelected(),
            hostPortsControl != null ? hostPortsControl.ports() : java.util.List.of(),
            effectiveRequestHeaders(),
            currentPayloadSet(),
            throttleControl != null ? throttleControl.posture()
                : com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.RIDE_HARD,
            payloadFamilyControl != null ? payloadFamilyControl.selection()
                : com.bypassfuzzer.burp.core.coverage.CoverageSweepFamilySelection.defaults(),
            throttleControl != null ? throttleControl.pauseMode()
                : com.bypassfuzzer.burp.core.throttle.ThrottleSettings.PauseMode.OFF,
            throttleControl != null ? throttleControl.fixedPauseMillis() : 30_000L,
            requestHeadersControl != null ? requestHeadersControl.userAgentMode()
                : UserAgentMode.DISABLED,
            userAgentRandomizationSeed
        );
    }

    /** Chrome desktop UA applied when the Browser User-Agent preset is enabled. */
    private static final String BROWSER_USER_AGENT =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/126.0.0.0 Safari/537.36";

    /**
     * The configured request headers, with a browser {@code User-Agent} prepended when the preset is
     * enabled and the user has not already supplied one of their own.
     */
    private java.util.List<com.bypassfuzzer.burp.http.ConfiguredHeader> effectiveRequestHeaders() {
        java.util.List<com.bypassfuzzer.burp.http.ConfiguredHeader> headers =
            requestHeadersControl == null ? java.util.List.of() : requestHeadersControl.headers();
        if (requestHeadersControl != null
            && requestHeadersControl.userAgentMode() != UserAgentMode.DISABLED) {
            return headers;
        }
        if (browserUserAgentCheckBox == null || !browserUserAgentCheckBox.isSelected()) {
            return headers;
        }
        boolean userSetUserAgent = headers.stream()
            .anyMatch(header -> header.name().equalsIgnoreCase("User-Agent"));
        if (userSetUserAgent) {
            return headers;
        }
        java.util.List<com.bypassfuzzer.burp.http.ConfiguredHeader> withUa =
            new java.util.ArrayList<>(headers.size() + 1);
        withUa.add(new com.bypassfuzzer.burp.http.ConfiguredHeader("User-Agent", BROWSER_USER_AGENT));
        withUa.addAll(headers);
        return withUa;
    }

    private CoverageSweepPayloadSet currentPayloadSet() {
        return payloadSetComboBox != null && payloadSetComboBox.getSelectedIndex() == 1
            ? CoverageSweepPayloadSet.ALL_PAYLOADS
            : CoverageSweepPayloadSet.HIGH_SIGNAL;
    }

    private Set<Integer> selectedStatuses() {
        Set<Integer> statuses = new LinkedHashSet<>();
        if (status401CheckBox != null && status401CheckBox.isSelected()) {
            statuses.add(401);
        }
        if (status403CheckBox != null && status403CheckBox.isSelected()) {
            statuses.add(403);
        }
        if (status3xxCheckBox != null && status3xxCheckBox.isSelected()) {
            addRange(statuses, 300, 399);
        }
        if (status4xxCheckBox != null && status4xxCheckBox.isSelected()) {
            addRange(statuses, 400, 499);
        }
        return Set.copyOf(statuses);
    }

    private void addRange(Set<Integer> statuses, int start, int end) {
        for (int status = start; status <= end; status++) {
            statuses.add(status);
        }
    }

    private void setStatusControlsEnabled(boolean enabled) {
        configurationControlsEnabled = enabled;
        status401CheckBox.setEnabled(enabled);
        status403CheckBox.setEnabled(enabled);
        status3xxCheckBox.setEnabled(enabled);
        status4xxCheckBox.setEnabled(enabled);
        throttleControl.setEnabled(enabled);
        payloadSetComboBox.setEnabled(enabled);
        payloadFamilyControl.setEnabled(enabled);
        requestHeadersControl.setEnabled(enabled);
        modeComboBox.setEnabled(enabled);
        updateBrowserUserAgentControl();
        updateModeControls();
    }

    private void updateBrowserUserAgentControl() {
        if (browserUserAgentCheckBox == null || requestHeadersControl == null) {
            return;
        }
        boolean randomized = requestHeadersControl.userAgentMode() != UserAgentMode.DISABLED;
        browserUserAgentCheckBox.setEnabled(configurationControlsEnabled && !randomized);
        browserUserAgentCheckBox.setToolTipText(randomized
            ? "Ignored while Request Headers User-Agent randomization is enabled."
            : "Send every probe with a current desktop Chrome User-Agent unless Request Headers supplies one.");
    }

    private CoverageSweepMode currentMode() {
        if (modeComboBox == null) {
            return CoverageSweepMode.BLOCKED_RESPONSES;
        }
        return switch (modeComboBox.getSelectedIndex()) {
            case 1 -> CoverageSweepMode.AUTHENTICATED_TRAFFIC;
            case 2 -> CoverageSweepMode.IMPORTED_TARGETS;
            default -> CoverageSweepMode.BLOCKED_RESPONSES;
        };
    }

    private CoverageSweepAuthSelection currentAuthSelection() {
        return new CoverageSweepAuthSelection(selectedAuthHeaders, selectedCookieNames,
            includeUnsafeMethodsCheckBox != null && includeUnsafeMethodsCheckBox.isSelected());
    }

    private void handleModeChange() {
        cachedHistoryCandidates = List.of();
        cachedHistoryPreview = null;
        importedOpenApiDocument = null;
        setCandidateRows(List.of());
        startButton.setEnabled(false);
        updateModeControls();
        statusLabel.setText(switch (currentMode()) {
            case AUTHENTICATED_TRAFFIC ->
                "Load in-scope 2xx Proxy history and choose identifiers used to recognize authenticated requests.";
            case IMPORTED_TARGETS ->
                "Import a text file containing one absolute HTTP or HTTPS URL per line.";
            case BLOCKED_RESPONSES ->
                "Load in-scope Proxy history responses to preview sweep candidates.";
        });
        updateEstimate();
    }

    private void updateModeControls() {
        if (modeComboBox == null) return;
        boolean idle = !engine.isRunning() && modeComboBox.isEnabled();
        boolean authenticated = currentMode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC;
        boolean imported = currentMode() == CoverageSweepMode.IMPORTED_TARGETS;
        boolean blocked = currentMode() == CoverageSweepMode.BLOCKED_RESPONSES;
        if (resultsWorkspace != null) {
            resultsWorkspace.setAuthVerificationTabsVisible(authenticated);
        }
        pullResponsesLabel.setVisible(blocked);
        status401CheckBox.setVisible(blocked);
        status403CheckBox.setVisible(blocked);
        status3xxCheckBox.setVisible(blocked);
        status4xxCheckBox.setVisible(blocked);
        status401CheckBox.setEnabled(idle && blocked);
        status403CheckBox.setEnabled(idle && blocked);
        status3xxCheckBox.setEnabled(idle && blocked);
        status4xxCheckBox.setEnabled(idle && blocked);
        loadButton.setVisible(!imported);
        loadButton.setEnabled(idle && !imported);
        importButton.setVisible(imported);
        importButton.setEnabled(idle && imported);
        importMenuButton.setVisible(imported);
        importMenuButton.setEnabled(idle && imported);
        clearImportButton.setVisible(imported);
        clearImportButton.setEnabled(idle && imported && candidateTableModel.getRowCount() > 0);
        includeUnsafeMethodsCheckBox.setVisible(authenticated || imported);
        includeUnsafeMethodsCheckBox.setEnabled(idle && (authenticated || imported));
        excludeStaticAssetsCheckBox.setVisible(authenticated);
        excludeStaticAssetsCheckBox.setEnabled(idle && authenticated);
        verifyUnauthenticatedAccessCheckBox.setVisible(authenticated);
        verifyUnauthenticatedAccessCheckBox.setEnabled(idle && authenticated);
        requestHeadersControl.button().setVisible(true);
        authIdentifiersButton.setVisible(authenticated);
        authIdentifiersButton.setEnabled(idle && authenticated);
        openApiBaseUrlLabel.setVisible(imported);
        openApiBaseUrlField.setVisible(imported);
        openApiBaseUrlField.setEnabled(idle && imported);
        applyOpenApiBaseUrlButton.setVisible(imported);
        applyOpenApiBaseUrlButton.setEnabled(idle && imported && importedOpenApiDocument != null);
        loadButton.setText(authenticated ? "Load Authenticated History" : "Load from Proxy History");
        revalidate();
        repaint();
    }

    private void clearImport() {
        if (currentMode() != CoverageSweepMode.IMPORTED_TARGETS || engine.isRunning()) {
            return;
        }
        setCandidateRows(List.of());
        cachedHistoryCandidates = List.of();
        cachedHistoryPreview = null;
        importedOpenApiDocument = null;
        openApiBaseUrlField.setText("");
        dedupeImportedEndpointsCheckBox.setSelected(false);
        startButton.setEnabled(false);
        setCandidateActionButtonsEnabled(false);
        clearImportButton.setEnabled(false);
        statusLabel.setText("Imported targets cleared. Import a file or OpenAPI URL to start fresh.");
        updateEstimate();
        updateModeControls();
    }

    private void selectObviousIdentifiers() {
        selectedAuthHeaders.add("Authorization");
        for (String header : discoveredAuthHeaders) {
            if (looksLikeAuthIdentifier(header)) selectedAuthHeaders.add(header);
        }
        for (String cookie : discoveredCookieNames) {
            if (looksLikeAuthIdentifier(cookie)) selectedCookieNames.add(cookie);
        }
    }

    private boolean looksLikeAuthIdentifier(String name) {
        String lower = name == null ? "" : name.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("auth") || lower.contains("session") || lower.contains("token")
            || lower.contains("jwt") || lower.equals("sid") || lower.endsWith("sid")
            || lower.contains("api-key") || lower.contains("apikey");
    }

    private void refilterAuthenticatedCandidates() {
        if (currentMode() != CoverageSweepMode.AUTHENTICATED_TRAFFIC) return;
        CoverageSweepAuthSelection selection = currentAuthSelection();
        List<CoverageSweepCandidate> filtered = cachedHistoryCandidates.stream()
            .filter(candidate -> selection.includeUnsafeMethods()
                || "GET".equalsIgnoreCase(candidate.method()) || "HEAD".equalsIgnoreCase(candidate.method()))
            .filter(candidate -> engine.matchesAuthSelection(candidate, selection))
            .limit(Math.max(1, CoverageSweepOptions.defaults().maxCandidates()))
            .toList();
        setCandidateRows(filtered);
        startButton.setEnabled(!filtered.isEmpty() && !engine.isRunning());
        if (cachedHistoryPreview != null) {
            updateAuthenticatedStatus(cachedHistoryPreview);
        }
        updateEstimate();
        updatePreviewButton();
    }

    private void handleUnsafeMethodsSelectionChange() {
        if (currentMode() == CoverageSweepMode.AUTHENTICATED_TRAFFIC) {
            refilterAuthenticatedCandidates();
        } else if (currentMode() == CoverageSweepMode.IMPORTED_TARGETS) {
            applyImportedMethodSelection();
        }
    }

    private void applyImportedMethodSelection() {
        candidateTableModel.setStateChangingMethodsSelected(includeUnsafeMethodsCheckBox.isSelected());
    }

    private void setCandidateRows(List<CoverageSweepCandidate> candidates) {
        importedControlResponses.clear();
        candidateTableModel.setCandidates(candidates);
        if (candidates == null || candidates.isEmpty()) {
            candidateTable.clearSelection();
            return;
        }
        candidateTable.setRowSelectionInterval(0, 0);
    }

    private void updateAuthenticatedStatus(CoverageSweepPreview preview) {
        statusLabel.setText("Inspected " + preview.inspectedHistoryCount() + " Proxy history item(s); "
            + preview.successfulResponseCount() + " had 2xx responses; "
            + preview.inScopeSuccessfulResponseCount() + " were in scope; "
            + preview.blockedHistoryCount() + " remained after static filtering; "
            + candidateTableModel.getRowCount() + " match the selected auth identifiers.");
    }

    private void openAuthIdentifiersDialog() {
        JPanel choices = new JPanel();
        choices.setLayout(new BoxLayout(choices, BoxLayout.Y_AXIS));
        choices.add(new JLabel("Headers used to identify authenticated requests:"));
        List<JCheckBox> headerBoxes = new ArrayList<>();
        Set<String> headers = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        headers.add("Authorization");
        headers.addAll(discoveredAuthHeaders);
        headers.addAll(selectedAuthHeaders);
        for (String name : headers) {
            JCheckBox box = new JCheckBox(name, selectedAuthHeaders.stream().anyMatch(name::equalsIgnoreCase));
            box.putClientProperty("identifier", name);
            headerBoxes.add(box);
            choices.add(box);
        }
        choices.add(new JLabel("Additional auth header names (comma-separated):"));
        JTextField customHeaders = new JTextField(30);
        choices.add(customHeaders);
        choices.add(new JLabel("Cookie names used only to identify authenticated requests:"));
        List<JCheckBox> cookieBoxes = new ArrayList<>();
        for (String name : new java.util.TreeSet<>(discoveredCookieNames)) {
            JCheckBox box = new JCheckBox(name, selectedCookieNames.contains(name));
            box.putClientProperty("identifier", name);
            cookieBoxes.add(box);
            choices.add(box);
        }
        choices.add(new JLabel("The entire Cookie header is removed from every attack request."));
        JScrollPane scroll = new JScrollPane(choices);
        scroll.setPreferredSize(new Dimension(520, 420));
        int result = JOptionPane.showConfirmDialog(this, scroll, "Authenticated Traffic Identifiers",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;
        selectedAuthHeaders = selectedIdentifiers(headerBoxes);
        for (String value : customHeaders.getText().split(",")) {
            if (!value.isBlank()) selectedAuthHeaders.add(value.trim());
        }
        selectedCookieNames = selectedIdentifiers(cookieBoxes);
        refilterAuthenticatedCandidates();
    }

    private Set<String> selectedIdentifiers(List<JCheckBox> boxes) {
        Set<String> selected = new LinkedHashSet<>();
        for (JCheckBox box : boxes) {
            if (box.isSelected()) selected.add(String.valueOf(box.getClientProperty("identifier")));
        }
        return selected;
    }

    private void updatePreviewButton() {
        boolean candidateAvailable = previewCandidate() != null;
        previewProbesButton.setEnabled(candidateAvailable && !engine.isRunning()
            && candidateLoadWorker == null && probePreviewWorker == null);
        viewCandidateButton.setEnabled(candidateAvailable && candidateLoadWorker == null);
    }

    private void setCandidateActionButtonsEnabled(boolean enabled) {
        if (previewProbesButton != null) previewProbesButton.setEnabled(enabled);
        if (viewCandidateButton != null) viewCandidateButton.setEnabled(enabled);
    }

    private void updateExportButton() {
        if (exportButton != null) {
            exportButton.setEnabled(resultsWorkspace != null
                && (resultsWorkspace.shownResultsCount() > 0
                    || resultsWorkspace.throttledRetryCount() > 0));
        }
    }

    private void exportResultsWithChooser() {
        if (resultsWorkspace.shownResultsCount() == 0) {
            statusLabel.setText("No visible sweep results to export.");
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Sweep Results TSV");
        chooser.setSelectedFile(new java.io.File("bypassfuzzer-sweep-results.tsv"));
        int result = chooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
        if (result != JFileChooser.APPROVE_OPTION || chooser.getSelectedFile() == null) {
            return;
        }

        exportResultsToTsv(chooser.getSelectedFile().toPath());
    }

    boolean exportResultsToTsv(Path path) {
        if (resultsWorkspace.shownResultsCount() == 0) {
            statusLabel.setText("No visible sweep results to export.");
            return false;
        }

        try {
            resultsWorkspace.writeVisibleResultsTsv(path);
            statusLabel.setText("Exported " + resultsWorkspace.shownResultsCount()
                + " visible sweep result(s) to " + path + ".");
            return true;
        } catch (Exception e) {
            statusLabel.setText("Unable to export sweep results: " + e.getMessage());
            try {
                JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Unable to export sweep results:\n" + e.getMessage(),
                    "Export Failed",
                    JOptionPane.ERROR_MESSAGE
                );
            } catch (Exception ignored) {
                // Headless tests or Burp shutdown can make dialogs unavailable.
            }
            return false;
        }
    }

    private CoverageSweepCandidate previewCandidate() {
        if (candidateTable == null || candidateTableModel.getRowCount() == 0) {
            return null;
        }
        int selectedViewRow = candidateTable.getSelectedRow();
        if (selectedViewRow >= 0) {
            return candidateTableModel.candidateAt(candidateTable.convertRowIndexToModel(selectedViewRow));
        }
        List<CoverageSweepCandidate> selectedCandidates = candidateTableModel.selectedCandidates();
        return selectedCandidates.isEmpty() ? null : selectedCandidates.get(0);
    }

    private void openCandidateView() {
        CoverageSweepCandidate candidate = previewCandidate();
        if (candidate == null) {
            statusLabel.setText("Select a candidate to view its original request and response.");
            return;
        }

        HttpRequestEditor requestViewer = api.userInterface().createHttpRequestEditor();
        HttpResponseEditor responseViewer = api.userInterface().createHttpResponseEditor();
        requestViewer.setRequest(candidate.request());
        HttpResponse originalResponse = originalResponseFor(candidate);
        responseViewer.setResponse(originalResponse);

        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestViewer.uiComponent(), BorderLayout.CENTER);

        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseViewer.uiComponent(), BorderLayout.CENTER);

        JSplitPane exchangeSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, responsePanel);
        exchangeSplit.setResizeWeight(0.5);

        JDialog dialog = new JDialog(
            api.userInterface().swingUtils().suiteFrame(),
            "Sweep Target - " + candidate.method() + " " + candidate.displayUrl(),
            false
        );
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setLayout(new BorderLayout(0, 8));
        dialog.add(exchangeSplit, BorderLayout.CENTER);
        if (originalResponse == null) {
            JLabel note = new JLabel("No response is available until the imported target's Control request runs.");
            note.setBorder(BorderFactory.createEmptyBorder(0, 8, 8, 8));
            dialog.add(note, BorderLayout.SOUTH);
        }
        dialog.setSize(1200, 720);
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        SwingUtilities.invokeLater(() -> exchangeSplit.setDividerLocation(0.5));
        dialog.setVisible(true);
    }

    private HttpResponse originalResponseFor(CoverageSweepCandidate candidate) {
        if (candidate == null) {
            return null;
        }
        return candidate.originalResponse() != null
            ? candidate.originalResponse()
            : importedControlResponses.get(candidate.request());
    }

    private void openProbePreview() {
        CoverageSweepCandidate candidate = previewCandidate();
        if (candidate == null) {
            statusLabel.setText("Select or check a candidate before previewing probes.");
            return;
        }

        CoverageSweepOptions options = currentOptions();
        if (options.payloadSet() == CoverageSweepPayloadSet.ALL_PAYLOADS) {
            if (probePreviewWorker != null) {
                return;
            }
            statusLabel.setText("Building full Bypass probe preview...");
            previewProbesButton.setEnabled(false);
            SwingWorker<List<CoverageSweepProbe>, Void> worker = new SwingWorker<>() {
                @Override
                protected List<CoverageSweepProbe> doInBackground() {
                    return engine.buildProbes(candidate, options);
                }

                @Override
                protected void done() {
                    if (probePreviewWorker != this) {
                        return;
                    }
                    try {
                        showProbePreview(candidate, get());
                        statusLabel.setText("Full Bypass probe preview ready.");
                    } catch (CancellationException e) {
                        statusLabel.setText("Probe preview cancelled.");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        statusLabel.setText("Probe preview interrupted.");
                    } catch (ExecutionException e) {
                        Throwable cause = e.getCause() == null ? e : e.getCause();
                        statusLabel.setText("Unable to build probe preview: "
                            + (cause.getMessage() == null ? "unknown error" : cause.getMessage()));
                    } finally {
                        probePreviewWorker = null;
                        updatePreviewButton();
                    }
                }
            };
            probePreviewWorker = worker;
            worker.execute();
            return;
        }
        showProbePreview(candidate, engine.buildProbes(candidate, options));
    }

    private void showProbePreview(CoverageSweepCandidate candidate, List<CoverageSweepProbe> probes) {
        JTextArea previewText = new JTextArea(renderProbePreview(candidate, probes));
        previewText.setEditable(false);
        previewText.setLineWrap(false);
        previewText.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewText.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(previewText);
        scrollPane.setPreferredSize(new Dimension(920, 620));

        JDialog dialog = new JDialog(api.userInterface().swingUtils().suiteFrame(), "Sweep Probe Preview", false);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        dialog.setLayout(new BorderLayout(0, 8));

        JLabel header = new JLabel(candidate.method() + " " + candidate.displayUrl() + " - " + probes.size() + " probe(s)");
        header.setBorder(BorderFactory.createEmptyBorder(8, 8, 0, 8));
        dialog.add(header, BorderLayout.NORTH);
        dialog.add(scrollPane, BorderLayout.CENTER);
        dialog.pack();
        dialog.setLocationRelativeTo(api.userInterface().swingUtils().suiteFrame());
        dialog.setVisible(true);
    }

    String renderProbePreview(CoverageSweepCandidate candidate, List<CoverageSweepProbe> probes) {
        StringBuilder builder = new StringBuilder();
        builder.append("Candidate: ")
            .append(candidate.method())
            .append(" ")
            .append(candidate.displayUrl())
            .append(System.lineSeparator())
            .append("Status: ")
            .append(candidate.statusCode())
            .append(System.lineSeparator())
            .append("Probe count: ")
            .append(probes.size())
            .append(System.lineSeparator())
            .append(System.lineSeparator());

        for (int index = 0; index < probes.size(); index++) {
            CoverageSweepProbe probe = probes.get(index);
            builder.append("===")
                .append(" ")
                .append(index + 1)
                .append(". ")
                .append(probe.family())
                .append(" - ")
                .append(probe.label())
                .append(" ")
                .append("===")
                .append(System.lineSeparator())
                .append(probe.request())
                .append(System.lineSeparator())
                .append(System.lineSeparator());
        }
        return builder.toString();
    }

    private static final class CandidateTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Run", "Method", "Host", "Path", "Status", "Content-Type"};
        private final List<Row> rows = new ArrayList<>();
        private boolean selectionEditingEnabled = true;

        void setSelectionEditingEnabled(boolean enabled) {
            selectionEditingEnabled = enabled;
            if (!rows.isEmpty()) {
                fireTableRowsUpdated(0, rows.size() - 1);
            }
        }

        void setSelectionEditingEnabledSilently(boolean enabled) {
            selectionEditingEnabled = enabled;
        }

        void setCandidates(List<CoverageSweepCandidate> candidates) {
            rows.clear();
            for (CoverageSweepCandidate candidate : candidates) {
                rows.add(new Row(true, candidate));
            }
            fireTableDataChanged();
        }

        List<CoverageSweepCandidate> selectedCandidates() {
            return rows.stream()
                .filter(row -> row.selected)
                .map(row -> row.candidate)
                .toList();
        }

        Map<String, Integer> hostCounts() {
            Map<String, Integer> counts = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            for (Row row : rows) {
                String host = row.candidate.host();
                counts.merge(host == null || host.isBlank() ? "unknown" : host, 1, Integer::sum);
            }
            return counts;
        }

        int excludeHosts(Set<String> excludedHosts) {
            if (excludedHosts == null || excludedHosts.isEmpty()) {
                return 0;
            }
            int removed = 0;
            for (Row row : rows) {
                if (excludedHosts.stream().anyMatch(host -> host.equalsIgnoreCase(row.candidate.host()))) {
                    if (row.selected) {
                        row.selected = false;
                    }
                    removed++;
                }
            }
            if (removed > 0) {
                fireTableDataChanged();
            }
            return removed;
        }

        void setStateChangingMethodsSelected(boolean selected) {
            for (Row row : rows) {
                String method = row.candidate.method();
                row.selected = selected || "GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method);
            }
            if (!rows.isEmpty()) {
                fireTableRowsUpdated(0, rows.size() - 1);
            }
        }

        void setSelectedAt(int modelRow, boolean selected) {
            if (modelRow >= 0 && modelRow < rows.size()) {
                rows.get(modelRow).selected = selected;
            }
        }

        CoverageSweepCandidate candidateAt(int rowIndex) {
            if (rowIndex < 0 || rowIndex >= rows.size()) {
                return null;
            }
            return rows.get(rowIndex).candidate;
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex == 0 ? Boolean.class : Object.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return selectionEditingEnabled && columnIndex == 0;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Row row = rows.get(rowIndex);
            CoverageSweepCandidate candidate = row.candidate;
            return switch (columnIndex) {
                case 0 -> row.selected;
                case 1 -> candidate.method();
                case 2 -> candidate.host();
                case 3 -> candidate.path();
                case 4 -> candidate.originalResponse() == null ? "Imported" : candidate.statusCode();
                case 5 -> candidate.contentType();
                default -> "";
            };
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && rowIndex >= 0 && rowIndex < rows.size()) {
                rows.get(rowIndex).selected = Boolean.TRUE.equals(value);
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }

        private static final class Row {
            private boolean selected;
            private final CoverageSweepCandidate candidate;

            private Row(boolean selected, CoverageSweepCandidate candidate) {
                this.selected = selected;
                this.candidate = candidate;
            }
        }
    }
}
