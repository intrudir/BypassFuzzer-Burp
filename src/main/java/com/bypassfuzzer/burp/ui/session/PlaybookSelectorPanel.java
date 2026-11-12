package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.core.scan.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;

/** Reusable catalog-backed selector; all displayed states derive from one immutable value. */
final class PlaybookSelectorPanel extends JPanel {
    private PlaybookSelection selection;
    private final Runnable changed;
    private final Map<String,JCheckBox> playbooks = new LinkedHashMap<>();
    private final Map<String,JCheckBox> groups = new LinkedHashMap<>();
    private final JLabel count = new JLabel();
    PlaybookSelectorPanel(PlaybookSelection selection, Runnable changed) {
        this.selection = selection; this.changed = changed;
        setLayout(new BorderLayout(8,8));
        var choices = new JPanel(); choices.setLayout(new BoxLayout(choices,BoxLayout.Y_AXIS));
        for (var descriptor : BypassPlaybooks.available(selection.inventory())) {
            String family = selection.group(descriptor);
            if (groups.containsKey(family)) continue;
            var group = new JCheckBox(family);
            group.setAlignmentX(Component.LEFT_ALIGNMENT); group.setFont(group.getFont().deriveFont(Font.BOLD));
            group.addActionListener(e -> setSelection(this.selection.withFamily(family, group.isSelected())));
            groups.put(family,group); choices.add(group);
            for (var d : BypassPlaybooks.available(selection.inventory())) {
                if (!selection.group(d).equals(family)) continue;
                var box = new JCheckBox(d.label()); box.setAlignmentX(Component.LEFT_ALIGNMENT);
                box.setBorder(BorderFactory.createEmptyBorder(2,20,2,0));
                box.setToolTipText(d.id()+" — "+d.description()+(d.http1Only()?" — HTTP/1 only":""));
                box.addActionListener(e -> setSelection(this.selection.withPlaybook(d.id(),box.isSelected())));
                playbooks.put(d.id(),box); choices.add(box);
            }
            choices.add(Box.createVerticalStrut(8));
        }
        var scroll = new JScrollPane(choices); scroll.getVerticalScrollBar().setUnitIncrement(24); scroll.setBorder(null);
        add(scroll,BorderLayout.CENTER);
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        var all = new JButton("Check All"); all.addActionListener(e -> setSelection(new PlaybookSelection(selection.inventory(), null)));
        var none = new JButton("Uncheck All"); none.addActionListener(e -> setSelection(new PlaybookSelection(selection.inventory(), Set.of())));
        actions.add(count); actions.add(all); actions.add(none); add(actions,BorderLayout.NORTH);
        com.bypassfuzzer.burp.ui.WorkbenchTheme.apply(this); refresh();
    }
    PlaybookSelection selection() { return selection; }
    void setSelection(PlaybookSelection value) { selection=value; refresh(); changed.run(); }
    void setFamily(String family, boolean enabled) { setSelection(selection.withFamily(family, enabled)); }
    private void refresh() {
        count.setText(selection.ids().size() + " playbooks selected");
        playbooks.forEach((id,box) -> box.setSelected(selection.ids().contains(id)));
        groups.forEach((group,box) -> {
            long total=BypassPlaybooks.available(selection.inventory()).stream().filter(d -> selection.group(d).equals(group)).count();
            long selected=BypassPlaybooks.available(selection.inventory()).stream().filter(d -> selection.group(d).equals(group) && selection.ids().contains(d.id())).count();
            box.setSelected(selected>0); box.setText(group + " (" + selected + "/" + total + ")");
            box.setToolTipText("Select or clear every playbook in this family");
        });
    }
}
