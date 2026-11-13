package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.core.http.UserAgentMode;
import com.bypassfuzzer.core.scan.RunConfiguration;
import javax.swing.*;
import java.awt.*;

/** A growing header editor above compact removal and User-Agent controls. */
final class RunHeaderFields extends JPanel {
    final JTextArea headers=new JTextArea(8,45);
    final JTextField removed=new JTextField();
    final JComboBox<UserAgentMode> userAgent=new JComboBox<>(UserAgentMode.values());
    RunHeaderFields(RunConfiguration configuration) {
        super(new BorderLayout(6,10));
        JPanel title=new JPanel(new BorderLayout(0,4));
        title.add(new JLabel("Headers to set"),BorderLayout.NORTH);
        title.add(new JLabel("One Name: value per line. Replaces the run’s configured header list."),BorderLayout.CENTER);
        add(title,BorderLayout.NORTH);
        headers.setName("runHeaders");headers.setText(configuration.headers().stream().map(h -> h.name()+": "+h.value()).collect(java.util.stream.Collectors.joining("\n")));
        add(new JScrollPane(headers),BorderLayout.CENTER);
        JPanel options=new JPanel(new GridLayout(0,2,8,10));
        options.add(new JLabel("Headers to remove (comma-separated)"));
        removed.setName("runRemoveHeaders");removed.setText(String.join(", ",configuration.removeHeaders()));options.add(removed);
        options.add(new JLabel("User-Agent variation"));userAgent.setName("runUserAgentMode");userAgent.setSelectedItem(configuration.userAgentMode());options.add(userAgent);
        add(options,BorderLayout.SOUTH);
    }
}
