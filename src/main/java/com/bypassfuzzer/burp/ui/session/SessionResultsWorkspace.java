package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.ExecutionPauseController;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.ResultFilterController;
import com.bypassfuzzer.burp.core.throttle.HostThrottleCoordinator;
import com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor;
import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import com.bypassfuzzer.burp.http.MontoyaRequestSender;
import com.bypassfuzzer.burp.http.RequestSender;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.WindowConstants;
import javax.swing.SwingWorker;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GraphicsEnvironment;
import java.awt.Dialog;
import java.awt.Window;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Shared filter/results workspace used by session tabs.
 */
public class SessionResultsWorkspace {

    private static final int SIDEBAR_WIDTH = 500;
    private static final int COLLAPSED_SIDEBAR_WIDTH = 58;

    private final ResultFilterController filterController = new ResultFilterController();
    private final FilterPanel filterPanel;
    private final SessionResultsPanel resultsPanel;
    private final JSplitPane splitPane;
    private final Consumer<SessionResultsWorkspace> filterAppliedListener;
    private final RequestSender retrySender;
    private final AtomicLong retryRequestsSent = new AtomicLong();
    private final JButton retryThrottledButton;
    private final JButton retryQueueButton;
    private final JLabel retryStatusLabel;
    private JPanel retryRow;
    private final Map<String, DeferredRetry> throttledRetries = new LinkedHashMap<>();
    private ThrottleSettings retryThrottleSettings = new ThrottleSettings(
        Set.of(429, 503), 1, 1, 400.0, ThrottleSettings.Posture.CONSERVATIVE);
    private Set<Integer> throttleStatusCodes = retryThrottleSettings.throttleStatusCodes();
    private boolean primaryRunActive;
    private volatile boolean retryRunning;
    private long queueGeneration;
    private SwingWorker<Void, RetryOutcome> retryWorker;
    private final ExecutionPauseController retryPauseController = new ExecutionPauseController();
    private volatile HostThrottleCoordinator retryCoordinator;
    private volatile boolean retryPaused;
    private volatile boolean retryStopRequested;
    private boolean filtersCollapsed;
    private Runnable throttleRetryQueueChangedListener = () -> { };
    private JDialog retryQueueDialog;
    private RetryQueueTableModel retryQueueTableModel;
    private JButton retryQueueExportButton;
    private Runnable retryQueueExportAction;
    private final SwingBatchDispatcher<AttackResult> pendingResults;
    private Consumer<List<AttackResult>> resultsChangedListener = ignored -> { };

    public SessionResultsWorkspace(MontoyaApi api,
                                   Consumer<String> errorLogger,
                                   Consumer<SessionResultsWorkspace> filterAppliedListener,
                                   SessionResultsPanel.ViewerLayout viewerLayout,
                                   SessionResultsPanel.TableLayout tableLayout,
                                   boolean borderlessSidebar) {
        this(api, errorLogger, filterAppliedListener, viewerLayout, tableLayout, borderlessSidebar,
            new MontoyaRequestSender(api));
    }

    public SessionResultsWorkspace(MontoyaApi api,
                                   Consumer<String> errorLogger,
                                   Consumer<SessionResultsWorkspace> filterAppliedListener,
                                   SessionResultsPanel.ViewerLayout viewerLayout,
                                   SessionResultsPanel.TableLayout tableLayout,
                                   boolean borderlessSidebar,
                                   GlobalTrafficGovernor globalGovernor) {
        this(api, errorLogger, filterAppliedListener, viewerLayout, tableLayout, borderlessSidebar,
            new MontoyaRequestSender(api, globalGovernor));
    }

    SessionResultsWorkspace(MontoyaApi api,
                            Consumer<String> errorLogger,
                            Consumer<SessionResultsWorkspace> filterAppliedListener,
                            SessionResultsPanel.ViewerLayout viewerLayout,
                            SessionResultsPanel.TableLayout tableLayout,
                            boolean borderlessSidebar,
                            RequestSender retrySender) {
        this.filterAppliedListener = filterAppliedListener == null ? workspace -> { } : filterAppliedListener;
        this.retrySender = retrySender;
        this.filterPanel = new FilterPanel(filterController.filterConfig(), errorLogger);
        this.filterPanel.setFilterChangeListener(this::applyFilters);
        this.resultsPanel = new SessionResultsPanel(api, filterController.highlighter(), this::applyFilters, viewerLayout, tableLayout);
        this.pendingResults = new SwingBatchDispatcher<>(this::addResults);
        this.retryThrottledButton = new JButton("Retry Queued (0)");
        this.retryThrottledButton.setEnabled(false);
        this.retryThrottledButton.setToolTipText(
            "Retry throttled and no-response requests, using control canaries for Sweep groups. "
                + "Unsafe methods require confirmation.");
        this.retryThrottledButton.addActionListener(event -> retryThrottledFromButton());
        this.retryQueueButton = new JButton("Retry queue (0)");
        this.retryQueueButton.setEnabled(false);
        this.retryQueueButton.setToolTipText(
            "View, export, and retry throttled or no-response requests.");
        this.retryQueueButton.addActionListener(event -> openRetryQueueDialog());
        this.retryStatusLabel = new JLabel("");
        this.splitPane = buildSplitPane(borderlessSidebar);
        updateFilterStatus();
        updateRetryControls();
    }

    public JSplitPane component() {
        return splitPane;
    }

    public void setAuthVerificationTabsVisible(boolean visible) {
        resultsPanel.setAuthVerificationTabsVisible(visible);
    }

    JButton retryThrottledButton() {
        return retryThrottledButton;
    }

    JLabel retryStatusLabel() {
        return retryStatusLabel;
    }

    public void applyFilters() {
        filterController.setHighlightColorFilter(filterPanel.selectedHighlightColor());
        resultsPanel.applyFilter(filterController::shouldShow);
        updateFilterStatus();
        filterAppliedListener.accept(this);
    }

    public void addResult(AttackResult result) {
        addResults(List.of(result));
    }

    /** Accepts results from scan workers with bounded Swing-queue backpressure. */
    public void enqueueResult(AttackResult result) {
        if (result == null) return;
        AttackResult durable = result.copyEvidenceToTempFile();
        if (SwingUtilities.isEventDispatchThread()) addResults(List.of(durable));
        else pendingResults.submit(durable);
    }

    /** Runs on the Swing thread after every previously enqueued result has been applied. */
    public void afterPendingResults(Runnable callback) {
        pendingResults.afterDrained(callback);
    }

    public void setResultsChangedListener(Consumer<List<AttackResult>> listener) {
        resultsChangedListener = listener == null ? ignored -> { } : listener;
    }

    private void addResults(List<AttackResult> additions) {
        for (AttackResult result : additions) filterController.track(result);
        resultsPanel.addResults(additions, filterController::shouldShow);
        for (AttackResult result : additions) {
            if (isRetryableResult(result)) trackThrottleResult(result);
            else removeThrottleRetry(result);
        }
        updateFilterStatus();
        updateRetryControls();
        resultsChangedListener.accept(additions);
    }

    public void clear() {
        cancelRetryWorker();
        pendingResults.clear();
        synchronized (throttledRetries) {
            throttledRetries.clear();
            queueGeneration++;
        }
        resultsPanel.clear();
        filterController.reset();
        updateFilterStatus();
        retryStatusLabel.setText("");
        updateRetryControls();
    }

    public void cleanup() {
        cancelRetryWorker();
        pendingResults.close();
        if (retryQueueDialog != null) retryQueueDialog.dispose();
    }

    /** Uses the run's centralized throttle settings for queue classification and retry pacing. */
    public void configureThrottleRetries(ThrottleSettings settings) {
        retryThrottleSettings = settings == null
            ? new ThrottleSettings(Set.of(), 1, 1, 400.0, ThrottleSettings.Posture.CONSERVATIVE)
            : settings;
        throttleStatusCodes = retryThrottleSettings.throttleStatusCodes();
        updateRetryControls();
    }

    /** Adds a mode-specific export to the otherwise shared retry-queue dialog. */
    public void setRetryQueueExportAction(Runnable action) {
        retryQueueExportAction = action;
        if (retryQueueExportButton != null) retryQueueExportButton.setVisible(action != null);
    }

    public void setPrimaryRunActive(boolean active) {
        if (active && !primaryRunActive) retryRequestsSent.set(0);
        primaryRunActive = active;
        updateRetryControls();
    }

    public long retryRequestCount() {
        return retryRequestsSent.get();
    }

    public int throttledRetryCount() {
        synchronized (throttledRetries) {
            return (int) throttledRetries.values().stream()
                .filter(retry -> !retry.patternBlocked())
                .count();
        }
    }

    public int patternBlockedRetryCount() {
        synchronized (throttledRetries) {
            return (int) throttledRetries.values().stream()
                .filter(DeferredRetry::patternBlocked)
                .count();
        }
    }

    public List<AttackResult> throttledRetrySnapshot() {
        synchronized (throttledRetries) {
            return throttledRetries.values().stream().map(DeferredRetry::result).toList();
        }
    }

    public void setThrottleRetryQueueChangedListener(Runnable listener) {
        throttleRetryQueueChangedListener = listener == null ? () -> { } : listener;
        updateRetryControls();
    }

    public boolean isRetryRunning() {
        return retryRunning;
    }

    public boolean isRetryPaused() {
        return retryRunning && retryPaused;
    }

    public String retryStatusText() {
        return retryStatusLabel.getText();
    }

    public void pauseThrottleRetry() {
        if (!retryRunning || retryPaused) return;
        retryPaused = true;
        retryPauseController.pause();
        HostThrottleCoordinator current = retryCoordinator;
        if (current != null) current.manualPause();
        retryStatusLabel.setText("Throttle retry pass paused. Already-sent requests may still finish.");
        updateRetryControls();
    }

    public void resumeThrottleRetry() {
        if (!retryRunning || !retryPaused) return;
        HostThrottleCoordinator current = retryCoordinator;
        if (current != null) current.manualResume();
        retryPaused = false;
        retryPauseController.resume();
        retryStatusLabel.setText("Throttle retry pass resumed...");
        updateRetryControls();
    }

    public void stopThrottleRetry() {
        if (!retryRunning) return;
        retryStopRequested = true;
        retryPaused = false;
        retryPauseController.resume();
        HostThrottleCoordinator current = retryCoordinator;
        if (current != null) current.manualResume();
        SwingWorker<Void, RetryOutcome> worker = retryWorker;
        if (worker != null) worker.cancel(true);
        retryStatusLabel.setText("Stopping throttle retry pass...");
        updateRetryControls();
    }

    void retryThrottled(boolean includeUnsafeMethods) {
        List<Map.Entry<String, DeferredRetry>> selected = new ArrayList<>();
        long generation;
        synchronized (throttledRetries) {
            if (retryRunning || primaryRunActive) {
                return;
            }
            for (Map.Entry<String, DeferredRetry> entry : throttledRetries.entrySet()) {
                if (!entry.getValue().patternBlocked()
                    && (includeUnsafeMethods || isSafeMethod(entry.getValue().result().getRequest()))) {
                    selected.add(Map.entry(entry.getKey(), entry.getValue()));
                }
            }
            if (selected.isEmpty()) {
                return;
            }
            selected.forEach(entry -> throttledRetries.remove(entry.getKey()));
            generation = queueGeneration;
            retryRunning = true;
            retryPaused = false;
            retryStopRequested = false;
            retryPauseController.reset();
        }

        retryStatusLabel.setText("Classifying and retrying " + selected.size()
            + " queued request(s)...");
        updateRetryControls();
        // Manual retries use the run's shared adaptive throttle settings. The controller learns from
        // each new response -- it does not replay the original 429, which previously compounded
        // backoff on every item.
        HostThrottleCoordinator coordinator = new HostThrottleCoordinator(
            retryThrottleSettings, (burp.api.montoya.MontoyaApi) null);
        retryCoordinator = coordinator;
        Set<String> processedKeys = ConcurrentHashMap.newKeySet();
        Map<String, List<Map.Entry<String, DeferredRetry>>> retryGroups = groupRetries(selected);
        retryWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                for (List<Map.Entry<String, DeferredRetry>> group : retryGroups.values()) {
                    if (!retryPauseController.awaitIfPaused(() -> !retryStopRequested && !isCancelled())
                        || retryStopRequested || isCancelled() || Thread.currentThread().isInterrupted()) {
                        break;
                    }

                    int firstRetryIndex = 0;
                    Map.Entry<String, DeferredRetry> sample = group.get(0);
                    HttpRequest controlRequest = sample.getValue().result().getOriginalRequest();
                    if (controlRequest != null) {
                        HttpResponse controlResponse = sendCoordinatedRetry(coordinator, controlRequest, this);
                        if (retryStopRequested || isCancelled() || Thread.currentThread().isInterrupted()) {
                            break;
                        }
                        if (controlResponse == null || isThrottleResponse(controlResponse)) {
                            break;
                        }

                        HttpResponse sampleResponse = sendCoordinatedRetry(
                            coordinator, sample.getValue().result().getRequest(), this);
                        if (retryStopRequested || isCancelled() || Thread.currentThread().isInterrupted()) {
                            break;
                        }
                        if (sampleResponse == null) {
                            break;
                        }
                        boolean stablePattern = isThrottleResponse(sampleResponse);
                        publish(new RetryOutcome(sample.getKey(), sample.getValue(), sampleResponse,
                            generation, stablePattern ? List.copyOf(group) : List.of()));
                        if (stablePattern) {
                            continue;
                        }
                        firstRetryIndex = 1;
                    }

                    for (int index = firstRetryIndex; index < group.size(); index++) {
                        Map.Entry<String, DeferredRetry> queued = group.get(index);
                        if (!retryPauseController.awaitIfPaused(() -> !retryStopRequested && !isCancelled())
                            || retryStopRequested || isCancelled() || Thread.currentThread().isInterrupted()) {
                            return null;
                        }
                        HttpResponse response = sendCoordinatedRetry(
                            coordinator, queued.getValue().result().getRequest(), this);
                        if (retryStopRequested || isCancelled() || Thread.currentThread().isInterrupted()) {
                            return null;
                        }
                        publish(new RetryOutcome(
                            queued.getKey(), queued.getValue(), response, generation, List.of()));
                    }
                }
                return null;
            }

            @Override
            protected void process(List<RetryOutcome> outcomes) {
                for (RetryOutcome outcome : outcomes) {
                    if (outcome.generation() != queueGeneration) {
                        continue;
                    }
                    int attempt = outcome.retry().result().getThrottleRetryAttempt() + 1;
                    AttackResult retryResult = AttackResult.throttleRetryOf(
                        outcome.retry().result(), outcome.response(), attempt);
                    addResult(retryResult);
                    if (outcome.stablePatternGroup().isEmpty()) {
                        processedKeys.add(outcome.key());
                    } else {
                        synchronized (throttledRetries) {
                            for (Map.Entry<String, DeferredRetry> stable : outcome.stablePatternGroup()) {
                                AttackResult stableResult = stable.getKey().equals(outcome.key())
                                    ? retryResult : stable.getValue().result();
                                throttledRetries.put(stable.getKey(), new DeferredRetry(stableResult, true));
                                processedKeys.add(stable.getKey());
                            }
                        }
                        retryStatusLabel.setText("Detected stable 429 pattern; quarantined "
                            + patternBlockedRetryCount() + " non-retryable request(s).");
                        updateRetryControls();
                    }
                }
            }

            @Override
            protected void done() {
                try {
                    get();
                } catch (CancellationException ignored) {
                } catch (Exception ignored) {
                } finally {
                    synchronized (throttledRetries) {
                        if (retryWorker != this) {
                            return;
                        }
                        for (Map.Entry<String, DeferredRetry> queued : selected) {
                            if (!processedKeys.contains(queued.getKey())) {
                                throttledRetries.putIfAbsent(queued.getKey(), queued.getValue());
                            }
                        }
                        retryRunning = false;
                        retryPaused = false;
                        retryWorker = null;
                        retryCoordinator = null;
                    }
                    int remaining = throttledRetryCount();
                    int stable = patternBlockedRetryCount();
                    retryStatusLabel.setText(retryStopRequested
                        ? "Throttle retry pass stopped; " + remaining + " request(s) remain queued."
                        : remaining == 0
                            ? "Throttle retry classification completed; no transient retries remain"
                                + (stable > 0 ? "; " + stable + " stable pattern-blocked 429(s) quarantined." : ".")
                            : "Throttle retry pass completed; " + remaining + " request(s) remain transient"
                                + (stable > 0 ? "; " + stable + " stable pattern-blocked 429(s) quarantined." : "."));
                    retryStopRequested = false;
                    updateRetryControls();
                }
            }
        };
        retryWorker.execute();
    }

    public int shownResultsCount() {
        return resultsPanel.shownResultsCount();
    }

    public int allResultsCount() {
        return resultsPanel.allResultsCount();
    }

    public List<AttackResult> allResults() {
        return resultsPanel.allResults();
    }

    public String visibleResultsAsTsv() {
        return resultsPanel.visibleRowsAsTsv();
    }

    public void writeVisibleResultsTsv(Path path) throws IOException {
        Files.writeString(path, visibleResultsAsTsv(), StandardCharsets.UTF_8);
    }

    private JSplitPane buildSplitPane(boolean borderlessSidebar) {
        JScrollPane filterScrollPane = new JScrollPane(filterPanel);
        filterScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        filterScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        filterScrollPane.setMinimumSize(new Dimension(0, 100));
        if (borderlessSidebar) {
            filterScrollPane.setBorder(null);
        }

        JPanel expandedFilterSidebar = new JPanel(new BorderLayout());
        JButton hideFiltersButton = new JButton("Hide Filters");
        hideFiltersButton.setToolTipText("Hide the filter drawer and give the results table more space.");
        expandedFilterSidebar.add(hideFiltersButton, BorderLayout.NORTH);
        expandedFilterSidebar.add(filterScrollPane, BorderLayout.CENTER);

        JPanel collapsedFilterSidebar = new JPanel(new BorderLayout());
        JButton showFiltersButton = new JButton("<html><center>Show<br>Filters</center></html>");
        showFiltersButton.setToolTipText("Show the filter drawer.");
        collapsedFilterSidebar.add(showFiltersButton, BorderLayout.CENTER);

        JPanel filterSidebar = new JPanel(new BorderLayout());
        filterSidebar.add(expandedFilterSidebar, BorderLayout.CENTER);
        hideFiltersButton.addActionListener(event -> {
            filtersCollapsed = true;
            filterSidebar.removeAll();
            filterSidebar.add(collapsedFilterSidebar, BorderLayout.CENTER);
            filterSidebar.setPreferredSize(new Dimension(COLLAPSED_SIDEBAR_WIDTH, 0));
            filterSidebar.revalidate();
            filterSidebar.repaint();
            splitPane.setDividerLocation(COLLAPSED_SIDEBAR_WIDTH);
        });
        showFiltersButton.addActionListener(event -> {
            filtersCollapsed = false;
            filterSidebar.removeAll();
            filterSidebar.add(expandedFilterSidebar, BorderLayout.CENTER);
            filterSidebar.setPreferredSize(new Dimension(SIDEBAR_WIDTH, 0));
            filterSidebar.revalidate();
            filterSidebar.repaint();
            splitPane.setDividerLocation(SIDEBAR_WIDTH);
        });

        JPanel resultsContainer = new JPanel(new BorderLayout());
        retryRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        retryRow.add(retryQueueButton);
        retryRow.add(retryStatusLabel);
        resultsContainer.add(retryRow, BorderLayout.NORTH);
        resultsContainer.add(resultsPanel, BorderLayout.CENTER);

        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, filterSidebar, resultsContainer);
        horizontalSplit.setDividerSize(6);
        horizontalSplit.setResizeWeight(0.0);
        if (borderlessSidebar) {
            horizontalSplit.setBorder(null);
        }
        SwingUtilities.invokeLater(() -> horizontalSplit.setDividerLocation(SIDEBAR_WIDTH));
        return horizontalSplit;
    }

    private void updateFilterStatus() {
        filterPanel.setFilterStatus(
            filterController.statusText(resultsPanel.shownResultsCount(), resultsPanel.allResultsCount())
        );
    }

    private void retryThrottledFromButton() {
        int unsafeCount;
        synchronized (throttledRetries) {
            unsafeCount = (int) throttledRetries.values().stream()
                .filter(retry -> !retry.patternBlocked())
                .filter(retry -> !isSafeMethod(retry.result().getRequest()))
                .count();
        }
        boolean includeUnsafe = false;
        if (unsafeCount > 0 && !GraphicsEnvironment.isHeadless()) {
            Object[] choices = {"Retry safe only", "Include unsafe", "Cancel"};
            int choice = JOptionPane.showOptionDialog(
                splitPane,
                unsafeCount + " queued request(s) use state-changing methods.\n"
                    + "Choose whether this pass should resend them.",
                "Retry Throttled Requests",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null,
                choices,
                choices[0]
            );
            if (choice == 2 || choice == JOptionPane.CLOSED_OPTION) {
                return;
            }
            includeUnsafe = choice == 1;
        }
        retryThrottled(includeUnsafe);
    }

    private void openRetryQueueDialog() {
        if (GraphicsEnvironment.isHeadless()) return;
        if (retryQueueDialog == null) {
            retryQueueTableModel = new RetryQueueTableModel();
            JTable table = new JTable(retryQueueTableModel);
            table.setAutoCreateRowSorter(true);
            table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
            JScrollPane scrollPane = new JScrollPane(table);
            scrollPane.setPreferredSize(new Dimension(900, 300));
            Window owner = SwingUtilities.getWindowAncestor(splitPane);
            retryQueueDialog = new JDialog(owner, "Deferred throttle retry queue",
                Dialog.ModalityType.MODELESS);
            retryQueueDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
            JPanel content = new JPanel(new BorderLayout(8, 8));
            content.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));
            content.add(scrollPane, BorderLayout.CENTER);

            retryQueueExportButton = new JButton("Export JSON...");
            retryQueueExportButton.setToolTipText("Export queued requests for later replay.");
            retryQueueExportButton.addActionListener(event -> {
                if (retryQueueExportAction != null) retryQueueExportAction.run();
            });
            retryQueueExportButton.setVisible(retryQueueExportAction != null);
            JButton closeButton = new JButton("Close");
            closeButton.addActionListener(event -> retryQueueDialog.setVisible(false));
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            buttons.add(retryThrottledButton);
            buttons.add(retryQueueExportButton);
            buttons.add(closeButton);
            JPanel retryControls = new JPanel(new BorderLayout());
            retryControls.add(retryStatusLabel, BorderLayout.CENTER);
            retryControls.add(buttons, BorderLayout.EAST);
            content.add(retryControls, BorderLayout.SOUTH);
            retryQueueDialog.setContentPane(content);
            retryQueueDialog.setSize(920, 380);
        }
        refreshRetryQueueDialog();
        retryQueueDialog.setLocationRelativeTo(SwingUtilities.getWindowAncestor(splitPane));
        retryQueueDialog.setVisible(true);
    }

    private void refreshRetryQueueDialog() {
        if (retryQueueTableModel == null) return;
        List<AttackResult> queued = throttledRetrySnapshot();
        retryQueueTableModel.setResults(queued);
        retryQueueDialog.setTitle("Deferred throttle retry queue (" + throttledRetryCount()
            + " retryable, " + patternBlockedRetryCount() + " stable pattern-blocked)");
        if (retryQueueExportButton != null) retryQueueExportButton.setEnabled(!queued.isEmpty());
    }

    private void trackThrottleResult(AttackResult result) {
        if (!isRetryableResult(result)) {
            return;
        }
        synchronized (throttledRetries) {
            String key = retryKey(result);
            DeferredRetry existing = throttledRetries.get(key);
            throttledRetries.put(key, new DeferredRetry(
                result, existing != null && existing.patternBlocked()));
        }
    }

    private boolean isRetryableResult(AttackResult result) {
        return result != null && result.getRequest() != null
            && (result.getResponse() == null || throttleStatusCodes.contains(result.getStatusCode()));
    }

    private void removeThrottleRetry(AttackResult result) {
        if (result == null || result.getRequest() == null) {
            return;
        }
        synchronized (throttledRetries) {
            throttledRetries.remove(retryKey(result));
        }
    }

    private String retryKey(AttackResult result) {
        HttpRequest request = result.getRequest();
        StringBuilder key = new StringBuilder();
        key.append(result.getAttackType()).append('\u0000')
            .append(result.getPayload()).append('\u0000')
            .append(result.getTargetLabel()).append('\u0000')
            .append(result.getPayloadFamily()).append('\u0000');
        try {
            HttpService service = request.httpService();
            if (service != null) {
                key.append(service.secure()).append(':').append(service.host()).append(':').append(service.port());
            }
            key.append('\u0000').append(request.toString());
        } catch (Exception e) {
            key.append(System.identityHashCode(request));
        }
        return key.toString();
    }

    private boolean isSafeMethod(HttpRequest request) {
        if (request == null || request.method() == null) {
            return false;
        }
        String method = request.method().toUpperCase(Locale.ROOT);
        return "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method);
    }

    private HttpResponse sendRetry(HttpRequest request,
                                   java.util.function.BooleanSupplier shouldContinue) {
        HttpMode mode = requestMode(request);
        retryRequestsSent.incrementAndGet();
        return mode == null
            ? retrySender.send(request, 30, TimeUnit.SECONDS, shouldContinue)
            : retrySender.send(request, mode, 30, TimeUnit.SECONDS, shouldContinue);
    }

    private HttpResponse sendCoordinatedRetry(HostThrottleCoordinator coordinator,
                                              HttpRequest request,
                                              SwingWorker<?, ?> worker) {
        java.util.function.BooleanSupplier shouldContinue = () -> retryPauseController.awaitIfPaused(
            () -> !retryStopRequested && worker != null && !worker.isCancelled());
        return coordinator.send(request, () -> sendRetry(request, shouldContinue), shouldContinue);
    }

    private boolean isThrottleResponse(HttpResponse response) {
        return response != null && throttleStatusCodes.contains((int) response.statusCode());
    }

    private Map<String, List<Map.Entry<String, DeferredRetry>>> groupRetries(
        List<Map.Entry<String, DeferredRetry>> selected) {
        Map<String, List<Map.Entry<String, DeferredRetry>>> groups = new LinkedHashMap<>();
        for (Map.Entry<String, DeferredRetry> entry : selected) {
            AttackResult result = entry.getValue().result();
            HttpRequest original = result.getOriginalRequest();
            String groupKey = original == null
                ? "single\u0000" + entry.getKey()
                : requestAuthority(original) + '\u0000' + result.getPayloadFamily()
                    + '\u0000' + result.getPayload();
            groups.computeIfAbsent(groupKey, ignored -> new ArrayList<>()).add(entry);
        }
        return groups;
    }

    private String requestAuthority(HttpRequest request) {
        try {
            HttpService service = request.httpService();
            if (service != null) {
                return service.secure() + ":" + service.host() + ":" + service.port();
            }
        } catch (Exception ignored) {
        }
        return request == null ? "" : request.url();
    }

    private HttpMode requestMode(HttpRequest request) {
        try {
            String version = request.httpVersion();
            if (version == null) {
                return null;
            }
            if (version.contains("2")) {
                return HttpMode.HTTP_2;
            }
            if (version.contains("1")) {
                return HttpMode.HTTP_1;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private void cancelRetryWorker() {
        SwingWorker<Void, RetryOutcome> worker = retryWorker;
        retryWorker = null;
        retryRunning = false;
        retryPaused = false;
        retryStopRequested = true;
        retryPauseController.resume();
        HostThrottleCoordinator current = retryCoordinator;
        retryCoordinator = null;
        if (current != null) current.manualResume();
        if (worker != null) {
            worker.cancel(true);
        }
    }

    private void updateRetryControls() {
        Runnable update = () -> {
            int count = throttledRetryCount();
            retryThrottledButton.setText("Retry Queued (" + count + ")");
            retryThrottledButton.setEnabled(count > 0 && !primaryRunActive && !retryRunning);
            int stable = patternBlockedRetryCount();
            retryQueueButton.setText(stable > 0
                ? "Retry queue (" + count + " retryable, " + stable + " stable)"
                : "Retry queue (" + count + ")");
            retryQueueButton.setEnabled(count + stable > 0);
            refreshRetryQueueDialog();
            throttleRetryQueueChangedListener.run();
        };
        if (SwingUtilities.isEventDispatchThread()) {
            update.run();
        } else {
            SwingUtilities.invokeLater(update);
        }
    }

    private record DeferredRetry(AttackResult result, boolean patternBlocked) {
        private DeferredRetry(AttackResult result) {
            this(result, false);
        }
    }

    private record RetryOutcome(String key, DeferredRetry retry, HttpResponse response, long generation,
                                List<Map.Entry<String, DeferredRetry>> stablePatternGroup) {
    }

    private static final class RetryQueueTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Target", "Method", "Payload", "Status", "Attempt"};
        private List<AttackResult> results = List.of();

        void setResults(List<AttackResult> results) {
            this.results = results == null ? List.of() : List.copyOf(results);
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            AttackResult result = results.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> result.getTargetLabel();
                case 1 -> result.getRequest() == null ? "" : result.getRequest().method();
                case 2 -> result.getPayload();
                case 3 -> result.getStatusCode();
                case 4 -> result.getThrottleRetryAttempt();
                default -> "";
            };
        }
    }

}
