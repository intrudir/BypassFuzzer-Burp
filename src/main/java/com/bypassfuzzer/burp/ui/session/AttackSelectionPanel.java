package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.ui.WorkbenchTheme;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class AttackSelectionPanel extends JPanel {

    private final JCheckBox headerAttackCheckbox;
    private final JCheckBox pathAttackCheckbox;
    private final JCheckBox verbAttackCheckbox;
    private final JCheckBox paramAttackCheckbox;
    private final JCheckBox trailingDotAttackCheckbox;
    private final JCheckBox trailingSlashAttackCheckbox;
    private final JCheckBox extensionAttackCheckbox;
    private final JCheckBox contentTypeAttackCheckbox;
    private final JCheckBox encodingAttackCheckbox;
    private final JCheckBox protocolAttackCheckbox;
    private final JCheckBox caseAttackCheckbox;
    private final JCheckBox cookieParamAttackCheckbox;
    private final JButton playbooksButton = new JButton("Playbooks…");
    private final JTextField apiPrefixes = new JTextField(18);
    private final JCheckBox calibration = new JCheckBox("Wildcard calibration", true);
    private com.bypassfuzzer.core.scan.PlaybookSelection selection;
    private Runnable changed;
    private JDialog playbooksDialog;
    private PlaybookSelectorPanel selector;
    private final JButton checkAllButton;
    private final JButton uncheckAllButton;

    public AttackSelectionPanel(FuzzerConfig config, Runnable onSelectionChanged) {
        selection = new com.bypassfuzzer.core.scan.PlaybookSelection(com.bypassfuzzer.core.scan.BypassPlaybooks.Inventory.BYPASS, config.getPlaybookOptions().selected());
        changed = onSelectionChanged;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("Attack families"));

        headerAttackCheckbox = createCheckbox("Header", config.isEnableHeaderAttack(), onSelectionChanged);
        pathAttackCheckbox = createCheckbox("Path", config.isEnablePathAttack(), onSelectionChanged);
        verbAttackCheckbox = createCheckbox("Verb", config.isEnableVerbAttack(), onSelectionChanged);
        paramAttackCheckbox = createCheckbox("Debug Params", config.isEnableParamAttack(), onSelectionChanged);
        trailingDotAttackCheckbox = createCheckbox("Trailing Dot", config.isEnableTrailingDotAttack(), onSelectionChanged);
        trailingSlashAttackCheckbox = createCheckbox("Trailing Slash", config.isEnableTrailingSlashAttack(), onSelectionChanged);
        extensionAttackCheckbox = createCheckbox("Extension", config.isEnableExtensionAttack(), onSelectionChanged);
        contentTypeAttackCheckbox = createCheckbox("Content-Type", config.isEnableContentTypeAttack(), onSelectionChanged);
        encodingAttackCheckbox = createCheckbox("Encoding", config.isEnableEncodingAttack(), onSelectionChanged);
        protocolAttackCheckbox = createCheckbox("Protocol", config.isEnableProtocolAttack(), onSelectionChanged);
        caseAttackCheckbox = createCheckbox("Case Variation", config.isEnableCaseAttack(), onSelectionChanged);
        cookieParamAttackCheckbox = createCheckbox("Debug Cookies", config.isEnableCookieParamAttack(), onSelectionChanged);

        JPanel row1 = new JPanel(new GridLayout(0, 6, 12, 6));
        row1.add(headerAttackCheckbox);
        row1.add(pathAttackCheckbox);
        row1.add(verbAttackCheckbox);
        row1.add(paramAttackCheckbox);
        row1.add(cookieParamAttackCheckbox);

        row1.add(trailingDotAttackCheckbox);
        row1.add(trailingSlashAttackCheckbox);
        row1.add(extensionAttackCheckbox);
        row1.add(contentTypeAttackCheckbox);
        row1.add(protocolAttackCheckbox);

        row1.add(encodingAttackCheckbox);
        row1.add(caseAttackCheckbox);
        add(row1);

        checkAllButton = new JButton("Check All");
        checkAllButton.addActionListener(e -> setAllSelected(true));

        uncheckAllButton = new JButton("Uncheck All");
        uncheckAllButton.addActionListener(e -> setAllSelected(false));

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        buttonRow.add(checkAllButton);
        buttonRow.add(uncheckAllButton);
        playbooksButton.addActionListener(e -> openPlaybooks());
        buttonRow.add(playbooksButton);
        add(buttonRow);
        apiPrefixes.setText(String.join(", ", config.getPlaybookOptions().apiPrefixes()));
        calibration.setSelected(config.getPlaybookOptions().wildcardCalibration());
        calibration.setToolTipText("Send a fresh sibling control for GET/HEAD seeds and annotate matching responses as Possible fallback.");
        apiPrefixes.setToolTipText("Additional path prefixes for API prefix insertion, separated by commas. For example: /internal-api, /gateway");
        apiPrefixes.getAccessibleContext().setAccessibleName("Additional API prefixes");
        syncFamiliesToSelection();
        updateSelectionState();
    }

    public boolean isHeaderAttackEnabled() {
        return headerAttackCheckbox.isSelected();
    }

    public boolean isPathAttackEnabled() {
        return pathAttackCheckbox.isSelected();
    }

    public boolean isVerbAttackEnabled() {
        return verbAttackCheckbox.isSelected();
    }

    public boolean isParamAttackEnabled() {
        return paramAttackCheckbox.isSelected();
    }

    public boolean isTrailingDotAttackEnabled() {
        return trailingDotAttackCheckbox.isSelected();
    }

    public boolean isTrailingSlashAttackEnabled() {
        return trailingSlashAttackCheckbox.isSelected();
    }

    public boolean isExtensionAttackEnabled() {
        return extensionAttackCheckbox.isSelected();
    }

    public boolean isContentTypeAttackEnabled() {
        return contentTypeAttackCheckbox.isSelected();
    }

    public boolean isEncodingAttackEnabled() {
        return encodingAttackCheckbox.isSelected();
    }

    public boolean isProtocolAttackEnabled() {
        return protocolAttackCheckbox.isSelected();
    }

    public boolean isCaseAttackEnabled() {
        return caseAttackCheckbox.isSelected();
    }

    public boolean isCookieParamAttackEnabled() {
        return cookieParamAttackCheckbox.isSelected();
    }

    public void setControlsEnabled(boolean enabled) {
        for (JCheckBox checkbox : allCheckboxes()) {
            checkbox.setEnabled(enabled);
        }
        checkAllButton.setEnabled(enabled);
        uncheckAllButton.setEnabled(enabled);
        playbooksButton.setEnabled(enabled); apiPrefixes.setEnabled(enabled); calibration.setEnabled(enabled);
        if (!enabled && playbooksDialog != null) playbooksDialog.setVisible(false);
    }

    private JCheckBox createCheckbox(String label, boolean selected, Runnable onSelectionChanged) {
        JCheckBox checkbox = new JCheckBox(label, selected);
        checkbox.addActionListener(e -> { syncFamiliesToSelection(); updateSelectionState(); onSelectionChanged.run(); });
        return checkbox;
    }

    private void setAllSelected(boolean selected) {
        for (JCheckBox checkbox : allCheckboxes()) {
            checkbox.setSelected(selected);
        }
        syncFamiliesToSelection(); updateSelectionState(); changed.run();
    }

    public com.bypassfuzzer.core.scan.PlaybookOptions playbookOptions() {
        var prefixes = java.util.Arrays.stream(apiPrefixes.getText().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
        return new com.bypassfuzzer.core.scan.PlaybookOptions(selection.ids(), prefixes, calibration.isSelected(), false);
    }
    private void syncFamiliesToSelection() {
        var boxes = allCheckboxes();
        var families = List.of("header", "path", "verb", "param", "trailingdot", "trailingslash", "extension", "contenttype", "encoding", "protocol", "case", "cookie");
        for (int i=0;i<boxes.size();i++) {
            boolean active=selection.groups().contains(families.get(i));
            if (active != boxes.get(i).isSelected()) selection=selection.withFamily(families.get(i), boxes.get(i).isSelected());
        }
    }
    private void updateSelectionState() {
        var families = List.of("header", "path", "verb", "param", "trailingdot", "trailingslash", "extension", "contenttype", "encoding", "protocol", "case", "cookie");
        for (int i=0;i<allCheckboxes().size();i++) allCheckboxes().get(i).setSelected(selection.groups().contains(families.get(i)));
        playbooksButton.setText("Playbooks… (" + selection.ids().size() + ")");
    }
    private void openPlaybooks() {
        if (playbooksDialog != null) playbooksDialog.dispose();
        playbooksDialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Bypass Playbooks", Dialog.ModalityType.MODELESS);
        selector = new PlaybookSelectorPanel(selection, () -> { selection=selector.selection(); updateSelectionState(); changed.run(); });
        JPanel content = new JPanel(new BorderLayout(0, 12));
        content.setBorder(BorderFactory.createEmptyBorder(12, 14, 10, 14));
        content.add(selector, BorderLayout.CENTER);
        var close = new JButton("Close");
        close.addActionListener(e -> playbooksDialog.setVisible(false));
        JPanel footer = new JPanel(new BorderLayout(0, 8));
        footer.add(buildScanBehaviorPanel(), BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        actions.add(close);
        footer.add(actions, BorderLayout.SOUTH);
        content.add(footer, BorderLayout.SOUTH);
        WorkbenchTheme.apply(content);
        playbooksDialog.setContentPane(content);
        playbooksDialog.setMinimumSize(new Dimension(620, 520));
        playbooksDialog.setSize(740, 720);
        playbooksDialog.setLocationRelativeTo(this);
        playbooksDialog.setVisible(true);
    }

    private JPanel buildScanBehaviorPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(WorkbenchTheme.sectionBorder("Scan behavior"));
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0; c.gridy = 0; c.gridwidth = 2; c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL; c.anchor = GridBagConstraints.WEST;
        panel.add(calibration, c);
        c.gridy++; c.insets = new Insets(0, 22, 12, 0);
        panel.add(WorkbenchTheme.muted("Flag generic fallback pages for GET and HEAD requests."), c);
        c.gridy++; c.gridwidth = 1; c.weightx = 0; c.insets = new Insets(0, 0, 0, 12);
        JLabel label = new JLabel("Additional API prefixes");
        label.setLabelFor(apiPrefixes);
        panel.add(label, c);
        c.gridx = 1; c.weightx = 1; c.insets = new Insets(0, 0, 0, 0);
        panel.add(apiPrefixes, c);
        c.gridy++; c.insets = new Insets(5, 0, 0, 0);
        panel.add(WorkbenchTheme.muted("Optional, comma-separated. Example: /internal-api, /gateway"), c);
        return panel;
    }

    private List<JCheckBox> allCheckboxes() {
        return List.of(
            headerAttackCheckbox,
            pathAttackCheckbox,
            verbAttackCheckbox,
            paramAttackCheckbox,
            trailingDotAttackCheckbox,
            trailingSlashAttackCheckbox,
            extensionAttackCheckbox,
            contentTypeAttackCheckbox,
            encodingAttackCheckbox,
            protocolAttackCheckbox,
            caseAttackCheckbox,
            cookieParamAttackCheckbox
        );
    }
}
