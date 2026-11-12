package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.config.FuzzerConfig;

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
    private final JButton checkAllButton;
    private final JButton uncheckAllButton;

    public AttackSelectionPanel(FuzzerConfig config, Runnable onSelectionChanged) {
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
        add(buttonRow);
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
    }

    private JCheckBox createCheckbox(String label, boolean selected, Runnable onSelectionChanged) {
        JCheckBox checkbox = new JCheckBox(label, selected);
        checkbox.addActionListener(e -> onSelectionChanged.run());
        return checkbox;
    }

    private void setAllSelected(boolean selected) {
        for (JCheckBox checkbox : allCheckboxes()) {
            checkbox.setSelected(selected);
        }
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
