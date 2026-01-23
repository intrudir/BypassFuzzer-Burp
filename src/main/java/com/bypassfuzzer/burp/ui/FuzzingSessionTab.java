package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.core.FuzzerEngine;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.filter.*;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Individual fuzzing session tab.
 * Each request sent to BypassFuzzer gets its own tab.
 */
public class FuzzingSessionTab extends JPanel {

    private final MontoyaApi api;
    private final FuzzerConfig config;
    private final FuzzerEngine engine;
    private final HttpRequest request;
    private final String tabTitle;

    private JButton startButton;
    private JButton stopButton;
    private JButton clearButton;
    private JLabel statusLabel;
    private JTable resultsTable;
    private FuzzerResultsTableModel tableModel;

    // Attack type checkboxes
    private JCheckBox headerAttackCheckbox;
    private JCheckBox pathAttackCheckbox;
    private JCheckBox verbAttackCheckbox;
    private JCheckBox paramAttackCheckbox;
    private JCheckBox trailingDotAttackCheckbox;
    private JCheckBox trailingSlashAttackCheckbox;
    private JCheckBox extensionAttackCheckbox;
    private JCheckBox contentTypeAttackCheckbox;
    private JCheckBox encodingAttackCheckbox;
    private JCheckBox protocolAttackCheckbox;
    private JCheckBox caseAttackCheckbox;
    private JCheckBox collaboratorCheckbox;
    private JCheckBox cookieParamAttackCheckbox;
    private JCheckBox fuzzExistingCookiesCheckbox;
    private JButton checkAllButton;
    private JButton uncheckAllButton;

    // Request/Response viewers
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // Row coloring - map result object to color
    private Map<AttackResult, Color> resultColors = new HashMap<>();
    private JPopupMenu tablePopupMenu;

    // Cleanup flag to prevent API calls during shutdown
    private volatile boolean isShuttingDown = false;

    // Filtering
    private FilterConfig filterConfig;
    private SmartFilter smartFilter;
    private ManualFilter manualFilter;
    private JCheckBox smartFilterCheckbox;
    private JCheckBox manualFilterCheckbox;
    private JTextField hideStatusCodesField;
    private JTextField showOnlyStatusCodesField;
    private JTextField minLengthField;
    private JTextField maxLengthField;
    private JTextField hideContentLengthsField;
    private JTextField showOnlyContentLengthsField;
    private JTextField contentTypeField;
    private JTextField payloadContainsField;
    private JComboBox<String> highlightColorFilter;
    private JButton applyFilterButton;
    private JLabel filterStatusLabel;
    private JLabel warningLabel;
    private JTextField requestsPerSecondField;
    private JTextField throttleStatusCodesField;

    public FuzzingSessionTab(MontoyaApi api, HttpRequest request) {
        this.api = api;
        this.request = request;
        this.config = new FuzzerConfig();
        this.engine = new FuzzerEngine(api, config);

        // Initialize filters
        this.filterConfig = new FilterConfig();
        this.smartFilter = new SmartFilter(filterConfig);
        this.manualFilter = new ManualFilter(filterConfig);

        // Create tab title from request
        String method = request.method();
        String path = extractPath(request.url());
        this.tabTitle = method + " " + truncate(path, 30);

        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        // Top panel - Controls and Attack Selection
        JPanel topPanel = new JPanel(new BorderLayout());

        // Control buttons
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startButton = new JButton("Start Fuzzing");
        startButton.addActionListener(e -> startFuzzing());

        stopButton = new JButton("Stop");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopFuzzing());

        clearButton = new JButton("Clear Results");
        clearButton.addActionListener(e -> clearResults());

        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(clearButton);

        // Attack type selection panel with wrapping layout
        JPanel attackPanel = new JPanel();
        attackPanel.setLayout(new BoxLayout(attackPanel, BoxLayout.Y_AXIS));
        attackPanel.setBorder(BorderFactory.createTitledBorder("Attack Types"));

        headerAttackCheckbox = new JCheckBox("Header", config.isEnableHeaderAttack());
        pathAttackCheckbox = new JCheckBox("Path", config.isEnablePathAttack());
        verbAttackCheckbox = new JCheckBox("Verb", config.isEnableVerbAttack());
        paramAttackCheckbox = new JCheckBox("Debug Params", config.isEnableParamAttack());
        trailingDotAttackCheckbox = new JCheckBox("Trailing Dot", config.isEnableTrailingDotAttack());
        trailingSlashAttackCheckbox = new JCheckBox("Trailing Slash", config.isEnableTrailingSlashAttack());
        extensionAttackCheckbox = new JCheckBox("Extension", config.isEnableExtensionAttack());
        contentTypeAttackCheckbox = new JCheckBox("Content-Type", config.isEnableContentTypeAttack());
        encodingAttackCheckbox = new JCheckBox("Encoding", config.isEnableEncodingAttack());
        protocolAttackCheckbox = new JCheckBox("Protocol", config.isEnableProtocolAttack());
        caseAttackCheckbox = new JCheckBox("Case Variation", config.isEnableCaseAttack());
        cookieParamAttackCheckbox = new JCheckBox("Debug Cookies", config.isEnableCookieParamAttack());

        // Add listeners to clear warning when checkboxes are changed
        headerAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        pathAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        verbAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        paramAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        trailingDotAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        trailingSlashAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        extensionAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        contentTypeAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        encodingAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        protocolAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        caseAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));
        cookieParamAttackCheckbox.addActionListener(e -> warningLabel.setVisible(false));

        // Row 1: Header, Path, Verb, Debug Params, Debug Cookies
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row1.add(headerAttackCheckbox);
        row1.add(pathAttackCheckbox);
        row1.add(verbAttackCheckbox);
        row1.add(paramAttackCheckbox);
        row1.add(cookieParamAttackCheckbox);
        attackPanel.add(row1);

        // Row 2: Trailing Dot, Trailing Slash, Extension, Content-Type, Protocol
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row2.add(trailingDotAttackCheckbox);
        row2.add(trailingSlashAttackCheckbox);
        row2.add(extensionAttackCheckbox);
        row2.add(contentTypeAttackCheckbox);
        row2.add(protocolAttackCheckbox);
        attackPanel.add(row2);

        // Row 3: Encoding, Case Variation
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row3.add(encodingAttackCheckbox);
        row3.add(caseAttackCheckbox);
        attackPanel.add(row3);

        // Add Check All / Uncheck All buttons
        checkAllButton = new JButton("Check All");
        checkAllButton.addActionListener(e -> {
            headerAttackCheckbox.setSelected(true);
            pathAttackCheckbox.setSelected(true);
            verbAttackCheckbox.setSelected(true);
            paramAttackCheckbox.setSelected(true);
            trailingDotAttackCheckbox.setSelected(true);
            trailingSlashAttackCheckbox.setSelected(true);
            extensionAttackCheckbox.setSelected(true);
            contentTypeAttackCheckbox.setSelected(true);
            encodingAttackCheckbox.setSelected(true);
            protocolAttackCheckbox.setSelected(true);
            caseAttackCheckbox.setSelected(true);
            cookieParamAttackCheckbox.setSelected(true);
        });

        uncheckAllButton = new JButton("Uncheck All");
        uncheckAllButton.addActionListener(e -> {
            headerAttackCheckbox.setSelected(false);
            pathAttackCheckbox.setSelected(false);
            verbAttackCheckbox.setSelected(false);
            paramAttackCheckbox.setSelected(false);
            trailingDotAttackCheckbox.setSelected(false);
            trailingSlashAttackCheckbox.setSelected(false);
            extensionAttackCheckbox.setSelected(false);
            contentTypeAttackCheckbox.setSelected(false);
            encodingAttackCheckbox.setSelected(false);
            protocolAttackCheckbox.setSelected(false);
            caseAttackCheckbox.setSelected(false);
            cookieParamAttackCheckbox.setSelected(false);
        });

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        buttonRow.add(checkAllButton);
        buttonRow.add(uncheckAllButton);
        attackPanel.add(buttonRow);

        // Options panel with vertical layout
        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createTitledBorder("Options"));

        // Collaborator row
        JPanel collabRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        collaboratorCheckbox = new JCheckBox("Include Collaborator payloads in headers?", config.isEnableCollaboratorPayloads());

        // Check if Collaborator is available
        boolean collaboratorAvailable = isCollaboratorAvailable();
        JLabel collabInfoIcon = null;
        if (!collaboratorAvailable) {
            collaboratorCheckbox.setEnabled(false);
            collaboratorCheckbox.setSelected(false);
            collaboratorCheckbox.setToolTipText("Burp Collaborator is not available. Requires Burp Suite Professional with Collaborator configured.");

            // Add info icon to indicate disabled state with tooltip
            collabInfoIcon = new JLabel("ⓘ");
            collabInfoIcon.setForeground(new java.awt.Color(100, 100, 100));
            collabInfoIcon.setToolTipText("Burp Collaborator is not available. Requires Burp Suite Professional with Collaborator configured.");
            collabInfoIcon.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        }

        collabRow.add(collaboratorCheckbox);
        if (collabInfoIcon != null) {
            collabRow.add(collabInfoIcon);
        }
        optionsPanel.add(collabRow);

        // Fuzz existing cookies row
        JPanel fuzzCookiesRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        fuzzExistingCookiesCheckbox = new JCheckBox("Debug Cookies: also fuzz existing cookies in request", config.isEnableFuzzExistingCookies());
        fuzzExistingCookiesCheckbox.setToolTipText("When enabled, tries debug values on cookies already in the request");
        fuzzCookiesRow.add(fuzzExistingCookiesCheckbox);
        optionsPanel.add(fuzzCookiesRow);

        // Rate limiting row
        JPanel rateRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        rateRow.add(new JLabel("Requests/second (0 = unlimited):"));
        requestsPerSecondField = new JTextField(String.valueOf(config.getRequestsPerSecond()), 5);
        rateRow.add(requestsPerSecondField);
        optionsPanel.add(rateRow);

        // Auto-throttle row
        JPanel throttleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        throttleRow.add(new JLabel("Auto-throttle for status code(s):"));
        throttleStatusCodesField = new JTextField(formatStatusCodes(config.getThrottleStatusCodes()), 10);
        throttleRow.add(throttleStatusCodesField);
        JLabel throttleHelp = new JLabel("(comma-separated, e.g., 429,503)");
        throttleHelp.setFont(throttleHelp.getFont().deriveFont(Font.ITALIC, 11f));
        throttleHelp.setForeground(Color.GRAY);
        throttleRow.add(throttleHelp);
        optionsPanel.add(throttleRow);

        // Status label
        statusLabel = new JLabel("Ready. Target: " + request.method() + " " + request.url());

        // Warning label for skipped attacks (initially hidden)
        warningLabel = new JLabel("");
        warningLabel.setForeground(new Color(204, 102, 0)); // Orange color
        warningLabel.setVisible(false);

        // Combine top panels using BoxLayout for better wrapping
        JPanel topContent = new JPanel();
        topContent.setLayout(new BoxLayout(topContent, BoxLayout.Y_AXIS));

        // Row 1: Control buttons and status
        JPanel topRow = new JPanel(new BorderLayout());
        topRow.add(controlPanel, BorderLayout.WEST);
        topRow.add(statusLabel, BorderLayout.CENTER);
        topContent.add(topRow);

        // Warning row (initially hidden)
        JPanel warningRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        warningRow.add(warningLabel);
        topContent.add(warningRow);

        // Row 2: Attack selection and options
        JPanel middleRow = new JPanel(new BorderLayout());
        middleRow.add(attackPanel, BorderLayout.CENTER);
        middleRow.add(optionsPanel, BorderLayout.EAST);
        topContent.add(middleRow);

        topPanel.add(topContent, BorderLayout.CENTER);

        // Filter panel (will be on left side)
        JPanel filterPanel = createFilterPanel();
        JScrollPane filterScrollPane = new JScrollPane(filterPanel);
        filterScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        filterScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        filterScrollPane.setMinimumSize(new Dimension(250, 100));

        // Center panel - Split pane with table on top and request/response on bottom
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.4); // 40% for table, 60% for viewers

        // Top of split - Results table with thread-safe model
        tableModel = new FuzzerResultsTableModel();
        resultsTable = new JTable(tableModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Initialize row sorter with proper numeric comparators
        initializeRowSorter();

        // Add selection listener to show request/response
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultsTable.getSelectedRow();
                if (selectedRow >= 0) {
                    // Convert view row to model row (in case table is sorted)
                    int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
                    showResultDetails(modelRow);
                }
            }
        });

        // Add custom cell renderer for row coloring and alignment
        resultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                // Left-align # and Attack Type columns
                if (column == 0 || column == 1) {
                    setHorizontalAlignment(SwingConstants.LEFT);
                } else {
                    setHorizontalAlignment(SwingConstants.LEFT);
                }

                if (!isSelected) {
                    // Convert view row to model row, then get the result object
                    int modelRow = table.convertRowIndexToModel(row);
                    AttackResult result = tableModel.getResult(modelRow);
                    if (result != null) {
                        Color rowColor = resultColors.get(result);
                        if (rowColor != null) {
                            c.setBackground(rowColor);
                            c.setForeground(Color.BLACK); // Ensure text is black for readability
                        } else {
                            c.setBackground(table.getBackground());
                            c.setForeground(table.getForeground());
                        }
                    } else {
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                    }
                }

                return c;
            }
        });

        // Create popup menu for coloring
        createTablePopupMenu();

        // Add right-click listener
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showPopup(e);
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showPopup(e);
                }
            }

            private void showPopup(MouseEvent e) {
                int row = resultsTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    resultsTable.setRowSelectionInterval(row, row);
                    tablePopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        // Set column widths - smaller for # and Attack Type
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);  // #
        resultsTable.getColumnModel().getColumn(0).setMaxWidth(50);         // # max width
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(60);  // Attack Type
        resultsTable.getColumnModel().getColumn(1).setMaxWidth(80);         // Attack Type max width
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(300); // Payload
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(60);  // Status
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(80);  // Length
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(150); // Content-Type

        JScrollPane tableScrollPane = new JScrollPane(resultsTable);

        // Create horizontal split: filters on LEFT, table on RIGHT
        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        horizontalSplit.setLeftComponent(filterScrollPane);
        horizontalSplit.setRightComponent(tableScrollPane);
        horizontalSplit.setDividerSize(6);
        horizontalSplit.setResizeWeight(0.0); // Give extra space to right (table) side

        // Set initial divider location for filters
        SwingUtilities.invokeLater(() -> {
            horizontalSplit.setDividerLocation(500); // Width for filter panel
        });

        // Request/Response viewers (full width)
        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();

        JTabbedPane viewerTabs = new JTabbedPane();
        viewerTabs.addTab("Request", requestViewer.uiComponent());
        viewerTabs.addTab("Response", responseViewer.uiComponent());

        // Vertical split: filters+table on top, viewers on bottom (full width)
        mainSplitPane.setTopComponent(horizontalSplit);
        mainSplitPane.setBottomComponent(viewerTabs);

        // Main layout: controls on top, main split below
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(mainSplitPane, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);

        // Bottom panel - Request info
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel(String.format("Target: %s %s", request.method(), request.url()));
        infoPanel.add(infoLabel);
        add(infoPanel, BorderLayout.SOUTH);
    }

    private JPanel createFilterPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Top section - Smart Filter
        JPanel smartPanel = new JPanel();
        smartPanel.setLayout(new BoxLayout(smartPanel, BoxLayout.Y_AXIS));
        smartPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        smartPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Smart Filter"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));

        smartFilterCheckbox = new JCheckBox("Enable (auto-detect patterns)");
        smartFilterCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        smartFilterCheckbox.addActionListener(e -> {
            filterConfig.setSmartFilterEnabled(smartFilterCheckbox.isSelected());
            applyFilters();
        });
        smartPanel.add(smartFilterCheckbox);

        smartPanel.add(Box.createVerticalStrut(5));
        filterStatusLabel = new JLabel("No filters active");
        filterStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        filterStatusLabel.setFont(filterStatusLabel.getFont().deriveFont(11f));
        smartPanel.add(filterStatusLabel);

        panel.add(smartPanel);
        panel.add(Box.createVerticalStrut(10));

        // Bottom section - Manual Filter
        JPanel manualPanel = new JPanel();
        manualPanel.setLayout(new BoxLayout(manualPanel, BoxLayout.Y_AXIS));
        manualPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        manualPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Manual Filter"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));

        // Manual filter checkbox
        manualFilterCheckbox = new JCheckBox("Enable Manual Filter");
        manualFilterCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        manualFilterCheckbox.addActionListener(e -> {
            boolean enabled = manualFilterCheckbox.isSelected();
            hideStatusCodesField.setEnabled(enabled);
            showOnlyStatusCodesField.setEnabled(enabled);
            minLengthField.setEnabled(enabled);
            maxLengthField.setEnabled(enabled);
            hideContentLengthsField.setEnabled(enabled);
            showOnlyContentLengthsField.setEnabled(enabled);
            contentTypeField.setEnabled(enabled);
            payloadContainsField.setEnabled(enabled);
            highlightColorFilter.setEnabled(enabled);
            applyFilterButton.setEnabled(enabled);

            // Toggle the filter config
            filterConfig.setManualFilterEnabled(enabled);

            // If disabling, also apply filters to update display
            if (!enabled) {
                applyFilters();
            }
        });
        manualPanel.add(manualFilterCheckbox);
        manualPanel.add(Box.createVerticalStrut(5));

        // Apply button at top for easy access
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        applyFilterButton = new JButton("Apply Manual Filters");
        applyFilterButton.setEnabled(false);
        applyFilterButton.addActionListener(e -> applyManualFilters());
        buttonPanel.add(applyFilterButton);
        manualPanel.add(buttonPanel);
        manualPanel.add(Box.createVerticalStrut(10));

        // Status Code Filters
        JPanel statusCodePanel = new JPanel();
        statusCodePanel.setLayout(new BoxLayout(statusCodePanel, BoxLayout.Y_AXIS));
        statusCodePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusCodePanel.setBorder(BorderFactory.createTitledBorder("Status Code"));

        JPanel hideStatusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        hideStatusRow.add(new JLabel("Hide codes:"));
        hideStatusCodesField = new JTextField(15);
        hideStatusCodesField.setToolTipText("Comma-separated, e.g., 404,403,500");
        hideStatusCodesField.setEnabled(false);
        hideStatusRow.add(hideStatusCodesField);
        hideStatusRow.add(new JLabel("(e.g. 404,403,500)"));
        hideStatusRow.add(Box.createHorizontalStrut(5));
        statusCodePanel.add(hideStatusRow);

        JPanel showStatusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        showStatusRow.add(new JLabel("Show only:"));
        showOnlyStatusCodesField = new JTextField(15);
        showOnlyStatusCodesField.setToolTipText("Comma-separated, e.g., 200,302");
        showOnlyStatusCodesField.setEnabled(false);
        showStatusRow.add(showOnlyStatusCodesField);
        showStatusRow.add(new JLabel("(e.g. 200,302)"));
        showStatusRow.add(Box.createHorizontalStrut(5));
        statusCodePanel.add(showStatusRow);

        manualPanel.add(statusCodePanel);
        manualPanel.add(Box.createVerticalStrut(5));

        // Length Filter
        JPanel lengthPanel = new JPanel();
        lengthPanel.setLayout(new BoxLayout(lengthPanel, BoxLayout.Y_AXIS));
        lengthPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        lengthPanel.setBorder(BorderFactory.createTitledBorder("Content Length (bytes)"));

        JPanel lengthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        lengthRow.add(new JLabel("Min:"));
        minLengthField = new JTextField(8);
        minLengthField.setToolTipText("Minimum bytes");
        minLengthField.setEnabled(false);
        lengthRow.add(minLengthField);
        lengthRow.add(new JLabel("Max:"));
        maxLengthField = new JTextField(8);
        maxLengthField.setToolTipText("Maximum bytes");
        maxLengthField.setEnabled(false);
        lengthRow.add(maxLengthField);
        lengthRow.add(new JLabel("(e.g. 1000 or 5000)"));
        lengthRow.add(Box.createHorizontalStrut(5));
        lengthPanel.add(lengthRow);

        JPanel hideLengthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        hideLengthRow.add(new JLabel("Hide lengths:"));
        hideContentLengthsField = new JTextField(15);
        hideContentLengthsField.setToolTipText("Comma-separated, e.g., 0,1234,5678");
        hideContentLengthsField.setEnabled(false);
        hideLengthRow.add(hideContentLengthsField);
        lengthPanel.add(hideLengthRow);

        JPanel showLengthRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        showLengthRow.add(new JLabel("Show only:"));
        showOnlyContentLengthsField = new JTextField(15);
        showOnlyContentLengthsField.setToolTipText("Comma-separated, e.g., 200,500");
        showOnlyContentLengthsField.setEnabled(false);
        showLengthRow.add(showOnlyContentLengthsField);
        lengthPanel.add(showLengthRow);

        manualPanel.add(lengthPanel);
        manualPanel.add(Box.createVerticalStrut(5));

        // Content-Type Filter
        JPanel contentTypePanel = new JPanel();
        contentTypePanel.setLayout(new BoxLayout(contentTypePanel, BoxLayout.Y_AXIS));
        contentTypePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        contentTypePanel.setBorder(BorderFactory.createTitledBorder("Content-Type"));

        JPanel contentTypeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        contentTypeRow.add(new JLabel("Contains:"));
        contentTypeField = new JTextField(20);
        contentTypeField.setToolTipText("Filter by content-type (e.g., 'json', 'html')");
        contentTypeField.setEnabled(false);
        contentTypeRow.add(contentTypeField);
        contentTypeRow.add(new JLabel("(e.g. html, json)"));
        contentTypeRow.add(Box.createHorizontalStrut(5));
        contentTypePanel.add(contentTypeRow);

        manualPanel.add(contentTypePanel);
        manualPanel.add(Box.createVerticalStrut(5));

        // Payload Contains Filter
        JPanel payloadPanel = new JPanel();
        payloadPanel.setLayout(new BoxLayout(payloadPanel, BoxLayout.Y_AXIS));
        payloadPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Payload"));

        JPanel payloadRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        payloadRow.add(new JLabel("Contains:"));
        payloadContainsField = new JTextField(20);
        payloadContainsField.setToolTipText("Filter by payload content (case-insensitive)");
        payloadContainsField.setEnabled(false);
        payloadRow.add(payloadContainsField);
        payloadPanel.add(payloadRow);

        manualPanel.add(payloadPanel);
        manualPanel.add(Box.createVerticalStrut(5));

        // Highlight Color Filter
        JPanel highlightPanel = new JPanel();
        highlightPanel.setLayout(new BoxLayout(highlightPanel, BoxLayout.Y_AXIS));
        highlightPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        highlightPanel.setBorder(BorderFactory.createTitledBorder("Highlight Color"));

        JPanel highlightRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        highlightRow.add(new JLabel("Show only:"));
        highlightColorFilter = new JComboBox<>(new String[]{
            "All",
            "Red",
            "Orange",
            "Yellow",
            "Green",
            "Blue",
            "Cyan",
            "Magenta",
            "Gray"
        });
        highlightColorFilter.setEnabled(false);
        highlightRow.add(highlightColorFilter);
        highlightPanel.add(highlightRow);

        manualPanel.add(highlightPanel);

        panel.add(manualPanel);

        return panel;
    }

    private void createTablePopupMenu() {
        tablePopupMenu = new JPopupMenu();

        // Color options with better contrast (darker backgrounds for readability)
        JMenuItem redItem = new JMenuItem("Highlight Red");
        redItem.addActionListener(e -> colorSelectedRow(new Color(255, 150, 150)));
        tablePopupMenu.add(redItem);

        JMenuItem orangeItem = new JMenuItem("Highlight Orange");
        orangeItem.addActionListener(e -> colorSelectedRow(new Color(255, 180, 120)));
        tablePopupMenu.add(orangeItem);

        JMenuItem yellowItem = new JMenuItem("Highlight Yellow");
        yellowItem.addActionListener(e -> colorSelectedRow(new Color(255, 255, 150)));
        tablePopupMenu.add(yellowItem);

        JMenuItem greenItem = new JMenuItem("Highlight Green");
        greenItem.addActionListener(e -> colorSelectedRow(new Color(150, 255, 150)));
        tablePopupMenu.add(greenItem);

        JMenuItem blueItem = new JMenuItem("Highlight Blue");
        blueItem.addActionListener(e -> colorSelectedRow(new Color(150, 200, 255)));
        tablePopupMenu.add(blueItem);

        JMenuItem cyanItem = new JMenuItem("Highlight Cyan");
        cyanItem.addActionListener(e -> colorSelectedRow(new Color(150, 255, 255)));
        tablePopupMenu.add(cyanItem);

        JMenuItem magentaItem = new JMenuItem("Highlight Magenta");
        magentaItem.addActionListener(e -> colorSelectedRow(new Color(255, 150, 255)));
        tablePopupMenu.add(magentaItem);

        JMenuItem grayItem = new JMenuItem("Highlight Gray");
        grayItem.addActionListener(e -> colorSelectedRow(new Color(200, 200, 200)));
        tablePopupMenu.add(grayItem);

        tablePopupMenu.addSeparator();

        JMenuItem clearItem = new JMenuItem("Clear Highlight");
        clearItem.addActionListener(e -> clearSelectedRowColor());
        tablePopupMenu.add(clearItem);
    }

    private void colorSelectedRow(Color color) {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
            AttackResult result = tableModel.getResult(modelRow);
            if (result != null) {
                resultColors.put(result, color);
                resultsTable.repaint();
            }
        }
    }

    private void clearSelectedRowColor() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = resultsTable.convertRowIndexToModel(selectedRow);
            AttackResult result = tableModel.getResult(modelRow);
            if (result != null) {
                resultColors.remove(result);
                resultsTable.repaint();
            }
        }
    }

    public String getTabTitle() {
        return tabTitle;
    }

    private void startFuzzing() {
        // Update config from checkboxes
        config.setEnableHeaderAttack(headerAttackCheckbox.isSelected());
        config.setEnablePathAttack(pathAttackCheckbox.isSelected());
        config.setEnableVerbAttack(verbAttackCheckbox.isSelected());
        config.setEnableParamAttack(paramAttackCheckbox.isSelected());
        config.setEnableTrailingDotAttack(trailingDotAttackCheckbox.isSelected());
        config.setEnableTrailingSlashAttack(trailingSlashAttackCheckbox.isSelected());
        config.setEnableExtensionAttack(extensionAttackCheckbox.isSelected());
        config.setEnableContentTypeAttack(contentTypeAttackCheckbox.isSelected());
        config.setEnableEncodingAttack(encodingAttackCheckbox.isSelected());
        config.setEnableProtocolAttack(protocolAttackCheckbox.isSelected());
        config.setEnableCaseAttack(caseAttackCheckbox.isSelected());
        config.setEnableCollaboratorPayloads(collaboratorCheckbox.isSelected());
        config.setEnableCookieParamAttack(cookieParamAttackCheckbox.isSelected());
        config.setEnableFuzzExistingCookies(fuzzExistingCookiesCheckbox.isSelected());

        // Read rate limiting settings
        try {
            int rps = Integer.parseInt(requestsPerSecondField.getText().trim());
            config.setRequestsPerSecond(Math.max(0, rps));
        } catch (NumberFormatException e) {
            config.setRequestsPerSecond(0); // Default to unlimited
        }

        // Parse throttle status codes
        config.setThrottleStatusCodes(parseStatusCodes(throttleStatusCodesField.getText()));
        config.setEnableAutoThrottle(!config.getThrottleStatusCodes().isEmpty());

        // Check if at least one attack is selected
        if (config.getAttackTypes().isEmpty()) {
            warningLabel.setText("⚠ Please select at least one attack type before starting!");
            warningLabel.setVisible(true);
            return;
        }

        // Warn if Collaborator is enabled but not available
        if (collaboratorCheckbox.isSelected() && !isCollaboratorAvailable()) {
            int choice = JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "Burp Collaborator is not available.\n" +
                "Collaborator requires Burp Suite Professional with Collaborator configured.\n\n" +
                "Continue fuzzing without Collaborator payloads?",
                "Collaborator Not Available",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

            if (choice != JOptionPane.YES_OPTION) {
                return;
            }

            // Disable collaborator in config since it's not available
            config.setEnableCollaboratorPayloads(false);
            collaboratorCheckbox.setSelected(false);
        }

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("Fuzzing in progress...");

        // Disable checkboxes during fuzzing
        setAttackCheckboxesEnabled(false);

        // Clear any previous warnings and check for new ones
        warningLabel.setVisible(false);

        List<String> warnings = new ArrayList<>();

        // Check if we're fuzzing root path and show warning
        String targetPath = extractPath(request.url());
        if ("/".equals(targetPath)) {
            List<String> skippedAttacks = new ArrayList<>();
            if (config.getAttackTypes().contains("path")) {
                skippedAttacks.add("Path");
            }
            if (config.getAttackTypes().contains("trailingslash")) {
                skippedAttacks.add("Trailing Slash");
            }
            if (config.getAttackTypes().contains("extension")) {
                skippedAttacks.add("Extension");
            }
            if (config.getAttackTypes().contains("encoding")) {
                skippedAttacks.add("Encoding");
            }

            if (!skippedAttacks.isEmpty()) {
                String warning = String.join(", ", skippedAttacks) +
                    " attack" + (skippedAttacks.size() > 1 ? "s" : "") +
                    " will be skipped (root path '/' detected)";
                warnings.add(warning);
            }
        }

        // Check if Content-Type attack will be skipped (non-body methods with no parameters)
        if (config.getAttackTypes().contains("contenttype")) {
            String method = request.method();
            if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH")) {
                // Check if there are any parameters (query or body)
                boolean hasParams = false;

                // Check query parameters
                String url = request.url();
                if (url != null && url.contains("?")) {
                    hasParams = true;
                }

                // Check body parameters
                if (!hasParams && request.body() != null && request.body().length() > 0) {
                    hasParams = true;
                }

                if (!hasParams) {
                    warnings.add("Content-Type attack will be skipped (" + method + " method with no parameters)");
                }
            }
        }

        // Display all warnings
        if (!warnings.isEmpty()) {
            String warningText = "⚠ Note: " + String.join("; ", warnings);
            warningLabel.setText(warningText);
            warningLabel.setVisible(true);
        }

        // Start fuzzing in background
        engine.startFuzzing(request, this::addResult);

        // Start a thread to monitor completion
        new Thread(() -> {
            try {
                // Poll every 500ms to check if fuzzing is complete
                while (engine.isRunning()) {
                    Thread.sleep(500);
                }
                // Fuzzing completed, update UI on Swing thread
                SwingUtilities.invokeLater(() -> {
                    if (!isShuttingDown && !engine.isRunning()) {
                        int totalSent = tableModel.getAllResultsCount();
                        int showing = tableModel.getRowCount();
                        statusLabel.setText("Completed: " + totalSent + " requests sent, showing " + showing);
                        startButton.setEnabled(true);
                        stopButton.setEnabled(false);
                        setAttackCheckboxesEnabled(true);
                    }
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }

    public void stopFuzzing() {
        engine.stopFuzzing();
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        statusLabel.setText("Stopped");
        setAttackCheckboxesEnabled(true);
    }

    /**
     * Cleanup when tab is closed or extension is unloaded.
     */
    public void cleanup() {
        isShuttingDown = true;
        engine.cleanup();
    }

    private void clearResults() {
        tableModel.clear();
        resultColors.clear();
        smartFilter.reset();
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
        statusLabel.setText("Results cleared");
        updateFilterStatus();
    }

    private void applyManualFilters() {
        // Parse hide status codes
        Set<Integer> hideStatusCodes = new HashSet<>();
        String hideText = hideStatusCodesField.getText().trim();
        if (!hideText.isEmpty()) {
            for (String code : hideText.split(",")) {
                try {
                    hideStatusCodes.add(Integer.parseInt(code.trim()));
                } catch (NumberFormatException e) {
                    api.logging().logToError("Invalid status code: " + code);
                }
            }
        }
        filterConfig.setHiddenStatusCodes(hideStatusCodes);

        // Parse show only status codes
        Set<Integer> showStatusCodes = new HashSet<>();
        String showText = showOnlyStatusCodesField.getText().trim();
        if (!showText.isEmpty()) {
            for (String code : showText.split(",")) {
                try {
                    showStatusCodes.add(Integer.parseInt(code.trim()));
                } catch (NumberFormatException e) {
                    api.logging().logToError("Invalid status code: " + code);
                }
            }
        }
        filterConfig.setShownStatusCodes(showStatusCodes);

        // Parse length range
        try {
            String minText = minLengthField.getText().trim();
            if (!minText.isEmpty()) {
                filterConfig.setMinContentLength(Integer.parseInt(minText));
            } else {
                filterConfig.setMinContentLength(null);
            }
        } catch (NumberFormatException e) {
            api.logging().logToError("Invalid min length: " + minLengthField.getText());
            filterConfig.setMinContentLength(null);
        }

        try {
            String maxText = maxLengthField.getText().trim();
            if (!maxText.isEmpty()) {
                filterConfig.setMaxContentLength(Integer.parseInt(maxText));
            } else {
                filterConfig.setMaxContentLength(null);
            }
        } catch (NumberFormatException e) {
            api.logging().logToError("Invalid max length: " + maxLengthField.getText());
            filterConfig.setMaxContentLength(null);
        }

        // Parse hide content lengths
        Set<Integer> hideContentLengths = new HashSet<>();
        String hideLengthText = hideContentLengthsField.getText().trim();
        if (!hideLengthText.isEmpty()) {
            for (String length : hideLengthText.split(",")) {
                try {
                    hideContentLengths.add(Integer.parseInt(length.trim()));
                } catch (NumberFormatException e) {
                    api.logging().logToError("Invalid content length: " + length);
                }
            }
        }
        filterConfig.setHiddenContentLengths(hideContentLengths);

        // Parse show only content lengths
        Set<Integer> showContentLengths = new HashSet<>();
        String showLengthText = showOnlyContentLengthsField.getText().trim();
        if (!showLengthText.isEmpty()) {
            for (String length : showLengthText.split(",")) {
                try {
                    showContentLengths.add(Integer.parseInt(length.trim()));
                } catch (NumberFormatException e) {
                    api.logging().logToError("Invalid content length: " + length);
                }
            }
        }
        filterConfig.setShownContentLengths(showContentLengths);

        // Parse content-type filter
        String contentTypeText = contentTypeField.getText().trim();
        if (!contentTypeText.isEmpty()) {
            filterConfig.setContentTypeFilter(contentTypeText);
        } else {
            filterConfig.setContentTypeFilter(null);
        }

        // Parse payload contains filter
        String payloadText = payloadContainsField.getText().trim();
        if (!payloadText.isEmpty()) {
            filterConfig.setPayloadContainsFilter(payloadText);
        } else {
            filterConfig.setPayloadContainsFilter(null);
        }

        applyFilters();
    }

    private void applyFilters() {
        // Save current sort state before rebuilding
        List<? extends javax.swing.RowSorter.SortKey> savedSortKeys = null;
        if (resultsTable.getRowSorter() != null) {
            savedSortKeys = new ArrayList<>(resultsTable.getRowSorter().getSortKeys());
        }

        // Apply filter using predicate - model handles the data internally
        tableModel.applyFilter(this::shouldShowResult);

        // Restore sorter with proper numeric comparators
        initializeRowSorter();

        // Restore previous sort state if any
        if (savedSortKeys != null && !savedSortKeys.isEmpty() && resultsTable.getRowSorter() != null) {
            try {
                resultsTable.getRowSorter().setSortKeys(savedSortKeys);
            } catch (Exception e) {
                // Ignore if sort keys can't be restored
            }
        }

        updateFilterStatus();
        resultsTable.repaint(); // Repaint to show any preserved colors
        api.logging().logToOutput("Filters applied: showing " + tableModel.getRowCount() + " of " + tableModel.getAllResultsCount() + " results");
    }

    private boolean shouldShowResult(AttackResult result) {
        // Check smart filter first
        if (!smartFilter.shouldShow(result)) {
            return false;
        }

        // Check manual filter
        if (filterConfig.isManualFilterEnabled() && !manualFilter.shouldShow(result)) {
            return false;
        }

        // Check highlight color filter
        if (filterConfig.isManualFilterEnabled() && highlightColorFilter.getSelectedIndex() > 0) {
            Color filterColor = getColorFromName((String) highlightColorFilter.getSelectedItem());
            Color resultColor = resultColors.get(result);

            // Only show if result has the selected highlight color
            if (!colorMatches(resultColor, filterColor)) {
                return false;
            }
        }

        return true;
    }

    private Color getColorFromName(String colorName) {
        switch (colorName) {
            case "Red": return new Color(255, 150, 150);
            case "Orange": return new Color(255, 180, 120);
            case "Yellow": return new Color(255, 255, 150);
            case "Green": return new Color(150, 255, 150);
            case "Blue": return new Color(150, 200, 255);
            case "Cyan": return new Color(150, 255, 255);
            case "Magenta": return new Color(255, 150, 255);
            case "Gray": return new Color(200, 200, 200);
            default: return null;
        }
    }

    private boolean colorMatches(Color c1, Color c2) {
        if (c1 == null || c2 == null) {
            return false;
        }
        return c1.getRed() == c2.getRed() &&
               c1.getGreen() == c2.getGreen() &&
               c1.getBlue() == c2.getBlue();
    }

    private void updateFilterStatus() {
        boolean anyFilterActive = filterConfig.isSmartFilterEnabled() || filterConfig.isManualFilterEnabled();

        if (!anyFilterActive) {
            filterStatusLabel.setText("No filters active");
        } else {
            StringBuilder status = new StringBuilder();
            if (filterConfig.isSmartFilterEnabled()) {
                status.append("Smart: ").append(smartFilter.getStatistics());
            }
            if (filterConfig.isManualFilterEnabled()) {
                if (status.length() > 0) {
                    status.append(" | ");
                }
                status.append("Manual: Active");
            }
            status.append(" | Showing ").append(tableModel.getRowCount()).append(" of ").append(tableModel.getAllResultsCount());
            filterStatusLabel.setText(status.toString());
        }
    }

    private void setAttackCheckboxesEnabled(boolean enabled) {
        // Don't modify UI during shutdown
        if (isShuttingDown) {
            return;
        }

        headerAttackCheckbox.setEnabled(enabled);
        pathAttackCheckbox.setEnabled(enabled);
        verbAttackCheckbox.setEnabled(enabled);
        paramAttackCheckbox.setEnabled(enabled);
        trailingDotAttackCheckbox.setEnabled(enabled);
        trailingSlashAttackCheckbox.setEnabled(enabled);
        extensionAttackCheckbox.setEnabled(enabled);
        contentTypeAttackCheckbox.setEnabled(enabled);
        encodingAttackCheckbox.setEnabled(enabled);
        protocolAttackCheckbox.setEnabled(enabled);
        caseAttackCheckbox.setEnabled(enabled);
        cookieParamAttackCheckbox.setEnabled(enabled);
        fuzzExistingCookiesCheckbox.setEnabled(enabled);
        checkAllButton.setEnabled(enabled);
        uncheckAllButton.setEnabled(enabled);

        // Disable rate limiting configuration during fuzzing
        requestsPerSecondField.setEnabled(enabled);
        throttleStatusCodesField.setEnabled(enabled);

        // Only enable collaborator checkbox if Collaborator is available
        if (enabled && isCollaboratorAvailable()) {
            collaboratorCheckbox.setEnabled(true);
        } else if (!enabled) {
            collaboratorCheckbox.setEnabled(false);
        }
        // If enabled=true but Collaborator not available, keep it disabled
    }

    /**
     * Initialize the row sorter with proper numeric comparators.
     */
    private void initializeRowSorter() {
        TableRowSorter<FuzzerResultsTableModel> sorter = new TableRowSorter<>(tableModel);
        // Column 0: # (Integer)
        sorter.setComparator(0, Comparator.comparingInt(o -> (Integer) o));
        // Column 3: Status (Integer)
        sorter.setComparator(3, Comparator.comparingInt(o -> (Integer) o));
        // Column 4: Length (Integer)
        sorter.setComparator(4, Comparator.comparingInt(o -> (Integer) o));
        resultsTable.setRowSorter(sorter);
    }

    private boolean isCollaboratorAvailable() {
        if (isShuttingDown) {
            return false;
        }
        try {
            return api.collaborator() != null && api.collaborator().defaultPayloadGenerator() != null;
        } catch (Exception e) {
            return false;
        }
    }

    private void addResult(AttackResult result) {
        // All UI and filter operations must happen on EDT to avoid deadlocks
        SwingUtilities.invokeLater(() -> {
            try {
                // Track pattern in smart filter
                smartFilter.track(result);

                // Check if result passes current filters (accesses Swing components)
                boolean passesFilter = shouldShowResult(result);

                // Add to model
                tableModel.addResult(result, passesFilter);

                // Update status
                int totalSent = tableModel.getAllResultsCount();
                int showing = tableModel.getRowCount();
                if (engine.isRunning()) {
                    statusLabel.setText("Fuzzing... (" + totalSent + " requests sent, showing " + showing + ")");
                } else {
                    statusLabel.setText("Completed: " + totalSent + " requests sent, showing " + showing);
                    startButton.setEnabled(true);
                    stopButton.setEnabled(false);
                    setAttackCheckboxesEnabled(true);
                }

                // Update filter status
                updateFilterStatus();
            } catch (Exception e) {
                api.logging().logToError("Error in addResult: " + e.getMessage());
            }
        });
    }

    private void showResultDetails(int modelRow) {
        AttackResult result = tableModel.getResult(modelRow);
        if (result != null) {
            // Display request and response in Burp's native editors
            if (result.getRequest() != null) {
                requestViewer.setRequest(result.getRequest());
            }

            if (result.getResponse() != null) {
                responseViewer.setResponse(result.getResponse());
            }
        }
    }

    private String extractPath(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                int pathStart = url.indexOf('/', schemeEnd + 3);
                if (pathStart != -1) {
                    return url.substring(pathStart);
                }
            }
            return "/";
        } catch (Exception e) {
            return "/";
        }
    }

    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength - 3) + "...";
    }

    /**
     * Format a set of status codes as comma-separated string.
     */
    private String formatStatusCodes(java.util.Set<Integer> codes) {
        if (codes == null || codes.isEmpty()) {
            return "429,503"; // Default
        }
        return codes.stream()
            .map(String::valueOf)
            .sorted()
            .collect(java.util.stream.Collectors.joining(","));
    }

    /**
     * Parse comma-separated status codes into a set.
     */
    private java.util.Set<Integer> parseStatusCodes(String input) {
        java.util.Set<Integer> codes = new java.util.HashSet<>();
        if (input == null || input.trim().isEmpty()) {
            return codes;
        }

        String[] parts = input.split(",");
        for (String part : parts) {
            try {
                int code = Integer.parseInt(part.trim());
                if (code >= 100 && code < 600) { // Valid HTTP status code range
                    codes.add(code);
                }
            } catch (NumberFormatException e) {
                // Skip invalid entries
            }
        }

        return codes;
    }
}
