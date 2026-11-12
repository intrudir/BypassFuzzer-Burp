package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.burp.core.attacks.AttackType;
import com.bypassfuzzer.burp.core.coverage.*;
import com.bypassfuzzer.core.scan.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.function.Supplier;

/** Independent inventory selections rendered by the same selector used in Bypass. */
final class CoverageSweepFamilyControl {
    private final Component owner;
    private final Supplier<CoverageSweepPayloadSet> payloadSetSupplier;
    private final Runnable onChange;
    private final HostPortsControl hostPortsControl;
    private final JButton button = new JButton("Payload Families...");
    private final PlaybookSelectorPanel highSignal;
    private final PlaybookSelectorPanel bypass;
    private final JTextField prefixes = new JTextField(22);
    private final JCheckBox calibration = new JCheckBox("Wildcard calibration", true);
    private JDialog dialog;
    private JTabbedPane tabs;
    private boolean enabled = true;
    CoverageSweepFamilyControl(Component owner, Supplier<CoverageSweepPayloadSet> payloadSetSupplier, Runnable onChange, HostPortsControl hostPortsControl) {
        this.owner=owner; this.payloadSetSupplier=payloadSetSupplier; this.onChange=onChange==null?()->{}:onChange; this.hostPortsControl=hostPortsControl;
        highSignal=new PlaybookSelectorPanel(new PlaybookSelection(BypassPlaybooks.Inventory.HIGH_SIGNAL,null),this::changed);
        bypass=new PlaybookSelectorPanel(new PlaybookSelection(BypassPlaybooks.Inventory.BYPASS,null),this::changed);
        button.addActionListener(e -> openDialog());
        button.setToolTipText("Playbooks… — choose exact checks or use family shortcuts; inventory selections are independent.");
    }
    JButton button() { return button; }
    void setEnabled(boolean value) { enabled=value; button.setEnabled(value); if (dialog != null && !value) dialog.setVisible(false); updateHostPortsEnabled(); }
    CoverageSweepFamilySelection selection() {
        var hs=highSignal.selection(); var all=bypass.selection();
        var families=new LinkedHashSet<AttackType>();
        for (var type:AttackType.values()) if (all.groups().contains(type.id())) families.add(type);
        var extras=Arrays.stream(prefixes.getText().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
        return new CoverageSweepFamilySelection(hs.groups(), families, new PlaybookOptions(hs.ids(),extras,calibration.isSelected(),false),
            new PlaybookOptions(all.ids(),extras,calibration.isSelected(),false));
    }
    void setHighSignalFamilyEnabled(String family, boolean value) { highSignal.setFamily(family,value); }
    void setBypassFamilyEnabled(AttackType family, boolean value) { bypass.setFamily(family.id(),value); }
    private void changed() { updateHostPortsEnabled(); onChange.run(); }
    private void updateHostPortsEnabled() { if (hostPortsControl != null) hostPortsControl.setEnabled(enabled && highSignal.selection().groups().contains("Host Parsing")); }
    private void openDialog() {
        if (dialog==null) {
            dialog=new JDialog(SwingUtilities.getWindowAncestor(owner),"Sweep Payload Families / Playbooks",Dialog.ModalityType.MODELESS);
            var content=buildDialogContent();
            dialog.setContentPane(content); dialog.setSize(760,720); dialog.setMinimumSize(new Dimension(560,400));
        }
        tabs.setSelectedIndex(payloadSetSupplier.get()==CoverageSweepPayloadSet.ALL_PAYLOADS?1:0);
        dialog.setLocationRelativeTo(owner); dialog.setVisible(true);
    }
    private JPanel buildDialogContent() {
            var content=new JPanel(new BorderLayout(8,8)); content.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
            var options=new JPanel(new GridLayout(0,1)); options.add(new JLabel("Separate selections for High signal and All payloads.")); options.add(calibration);
            var extra=new JPanel(new FlowLayout(FlowLayout.LEFT)); extra.add(new JLabel("Additional API prefixes:")); extra.add(prefixes); options.add(extra);
            content.add(options,BorderLayout.NORTH); tabs=new JTabbedPane();
            var hs=new JPanel(new BorderLayout()); hs.add(highSignal);
            if(hostPortsControl!=null) hs.add(hostPortsControl.configurationPanel(),BorderLayout.SOUTH);
            tabs.addTab("High Signal",hs); tabs.addTab("All Bypass Families",bypass); content.add(tabs);
            var close=new JButton("Close"); close.addActionListener(e -> { if(dialog != null) dialog.setVisible(false); onChange.run(); });
            var footer=new JPanel(new FlowLayout(FlowLayout.RIGHT)); footer.add(close); content.add(footer,BorderLayout.SOUTH);
        return content;
    }

}
