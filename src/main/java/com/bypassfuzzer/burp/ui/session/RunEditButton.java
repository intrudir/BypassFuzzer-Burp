package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.core.scan.*;
import com.bypassfuzzer.core.http.*;
import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.function.*;

/** The same pause/edit/resume dialog in every attack workspace. */
public final class RunEditButton extends JButton {
    private final Supplier<LiveRun> run;
    private final BooleanSupplier active;
    private final Runnable pause,resume;
    private final javax.swing.Timer availability;
    public RunEditButton(Supplier<LiveRun> run,BooleanSupplier active,Runnable pause,Runnable resume) {
        super("Edit run…");setName("editRunButton");this.run=run;this.active=active;this.pause=pause;this.resume=resume;
        setToolTipText("Pause, edit scope, throttle, playbooks or headers, then apply and resume.");
        setEnabled(false);availability=new javax.swing.Timer(200,e -> {
            LiveRun current=run.get();setEnabled(active.getAsBoolean() && current!=null);
            setText(current!=null && current.snapshot().revision()>0 ? "Edit run… (r"+current.snapshot().revision()+")" : "Edit run…");
        });
        addActionListener(e -> {pause.run();LiveRun current=run.get();if(current!=null)showEditor(this,current,resume);});
    }
    @Override public void addNotify(){super.addNotify();availability.start();}
    @Override public void removeNotify(){availability.stop();super.removeNotify();}
    private static JScrollPane scrollList(JPanel list) {
        var scroll=new JScrollPane(list);scroll.getVerticalScrollBar().setUnitIncrement(24);return scroll;
    }
    public static void showEditor(Component owner,LiveRun run,Runnable resume) {
        var initial=run.snapshot();var config=initial.configuration();
        JDialog dialog=new JDialog(SwingUtilities.getWindowAncestor(owner),"Edit paused run",Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setName("editRunDialog");dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        JPanel content=new JPanel(new BorderLayout(10,10));content.setBorder(BorderFactory.createEmptyBorder(14,14,14,14));
        JLabel status=new JLabel("Pausing…");status.setName("editRunStatus");content.add(status,BorderLayout.NORTH);
        JTabbedPane tabs=new JTabbedPane();
        JPanel scope=new JPanel();scope.setLayout(new BoxLayout(scope,BoxLayout.Y_AXIS));
        scope.add(new JLabel("Exclude checked hosts from the remaining work in this run."));
        Map<String,JCheckBox> hostChecks=new LinkedHashMap<>();var hosts=new TreeSet<>(run.hosts());hosts.addAll(config.excludedHosts());
        for(String host:hosts){var box=new JCheckBox(host,config.excludes(host));box.setName("excludeHost:"+host);hostChecks.put(host,box);scope.add(box);}
        tabs.addTab("Scope",scrollList(scope));
        JPanel throttle=new JPanel(new GridLayout(0,2,8,12));
        var total=new JSpinner(new SpinnerNumberModel(config.concurrency(),1,Integer.MAX_VALUE,1));total.setName("runConcurrency");
        var perHost=new JSpinner(new SpinnerNumberModel(config.perHostConcurrency(),1,Integer.MAX_VALUE,1));perHost.setName("runPerHostConcurrency");
        var rate=new JSpinner(new SpinnerNumberModel(config.requestsPerSecond(),0.1,Double.MAX_VALUE,1d));rate.setName("runRequestsPerSecond");
        throttle.add(new JLabel("Total concurrency"));throttle.add(total);throttle.add(new JLabel("Per-host concurrency"));throttle.add(perHost);
        throttle.add(new JLabel("Per-host requests/second cap"));throttle.add(rate);JPanel throttlePage=new JPanel(new BorderLayout());throttlePage.add(throttle,BorderLayout.NORTH);tabs.addTab("Throttle",throttlePage);
        JPanel checks=new JPanel();checks.setLayout(new BoxLayout(checks,BoxLayout.Y_AXIS));
        Map<String,JCheckBox> playbooks=new LinkedHashMap<>();
        run.availablePlaybooks().forEach((id,label) -> {var box=new JCheckBox(label,config.playbooks()==null || config.playbooks().contains(id));box.setName("runPlaybook:"+id);box.setToolTipText(id);playbooks.put(id,box);checks.add(box);});
        if(playbooks.isEmpty())checks.add(new JLabel("This replay keeps its exact saved request inventory."));
        JPanel checkPanel=new JPanel(new BorderLayout(4,4));JPanel checkActions=new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton all=new JButton("Select all");all.addActionListener(e -> playbooks.values().forEach(box -> box.setSelected(true)));
        JButton none=new JButton("Clear selection");none.addActionListener(e -> playbooks.values().forEach(box -> box.setSelected(false)));
        checkActions.add(all);checkActions.add(none);checkPanel.add(checkActions,BorderLayout.NORTH);checkPanel.add(scrollList(checks),BorderLayout.CENTER);
        tabs.addTab("Playbooks",checkPanel);
        var headerFields=new RunHeaderFields(config);
        JTextArea headerText=headerFields.headers;
        JTextField removed=headerFields.removed;
        JComboBox<UserAgentMode> ua=headerFields.userAgent;
        tabs.addTab("Headers",headerFields);content.add(tabs,BorderLayout.CENTER);
        JPanel footer=new JPanel(new BorderLayout());JLabel error=new JLabel(" ");error.setName("editRunError");footer.add(error,BorderLayout.CENTER);
        JPanel actions=new JPanel(new FlowLayout(FlowLayout.RIGHT));JButton cancel=new JButton("Keep paused");cancel.addActionListener(e -> dialog.dispose());
        JButton apply=com.bypassfuzzer.burp.ui.WorkbenchTheme.primary(new JButton("Apply & Resume"));apply.setName("applyRunConfiguration");apply.setEnabled(false);
        apply.addActionListener(e -> {
            try {
                total.commitEdit();perHost.commitEdit();rate.commitEdit();
                Set<String> excluded=new LinkedHashSet<>();hostChecks.forEach((host,box) -> {if(box.isSelected())excluded.add(host);});
                Set<String> selected=new LinkedHashSet<>();playbooks.forEach((id,box) -> {if(box.isSelected())selected.add(id);});
                Set<String> remove=new LinkedHashSet<>();for(String name:removed.getText().split(","))if(!name.isBlank())remove.add(name.trim());
                if(run.snapshot().revision()!=initial.revision())throw new IllegalStateException("Configuration changed; reopen the editor.");
                var dangerous=IdorPanel.newlyEnabledDangerousFamilies(config.playbooks()==null ? Set.of() : config.playbooks(),selected);
                if(!dangerous.isEmpty()) {
                    String risks=dangerous.stream().map(id -> id+": "+new IdorPlanner().dangerousFamilyRisks().get(id)).collect(java.util.stream.Collectors.joining("\n\n"));
                    if(JOptionPane.showConfirmDialog(dialog,risks+"\n\nEnable these DANGEROUS playbooks?","DANGEROUS: IDOR identifier probes",JOptionPane.YES_NO_OPTION,JOptionPane.WARNING_MESSAGE)!=JOptionPane.YES_OPTION)return;
                }
                run.apply(new RunConfiguration(excluded,((Number)total.getValue()).intValue(),((Number)perHost.getValue()).intValue(),((Number)rate.getValue()).doubleValue(),
                    config.playbooks()==null && playbooks.isEmpty() ? null : selected,ConfiguredHeaderParser.parse(headerText.getText()),remove,(UserAgentMode)ua.getSelectedItem(),config.userAgentSeed()));
                resume.run();dialog.dispose();
            }catch(Exception failure){error.setText(failure.getMessage());error.setToolTipText(failure.getMessage());}
        });
        actions.add(cancel);actions.add(apply);footer.add(actions,BorderLayout.SOUTH);content.add(footer,BorderLayout.SOUTH);
        javax.swing.Timer timer=new javax.swing.Timer(100,e -> {
            var snapshot=run.snapshot();apply.setEnabled(snapshot.state()==LiveRun.State.PAUSED);
            status.setText(snapshot.state()==LiveRun.State.PAUSING ? "Pausing… · "+snapshot.inFlight()+" request(s) finishing" : snapshot.state()==LiveRun.State.PAUSED ? "Paused · edits apply to remaining work; completed results are retained" : "Run is no longer paused");
        });
        dialog.addWindowListener(new java.awt.event.WindowAdapter(){@Override public void windowClosed(java.awt.event.WindowEvent e){timer.stop();}});
        com.bypassfuzzer.burp.ui.WorkbenchTheme.apply(content);dialog.setContentPane(content);dialog.setMinimumSize(new Dimension(620,430));dialog.setSize(740,560);dialog.setLocationRelativeTo(SwingUtilities.getWindowAncestor(owner));timer.start();dialog.setVisible(true);
    }
}
