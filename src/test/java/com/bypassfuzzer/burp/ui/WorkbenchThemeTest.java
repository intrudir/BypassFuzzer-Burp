package com.bypassfuzzer.burp.ui;

import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.awt.Color;
import static org.junit.jupiter.api.Assertions.*;

class WorkbenchThemeTest {
    @Test
    void staysInsideTheExtensionAndStylesNewChildren() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            Object buttonDefault = UIManager.get("Button.background");
            Object tabDefault = UIManager.get("TabbedPaneUI");
            JPanel hostEditor = new JPanel();
            hostEditor.setBackground(Color.PINK);
            JPanel root = new JPanel();
            root.add(WorkbenchTheme.nativeEditor(hostEditor));
            WorkbenchTheme.apply(root);
            JButton newSessionAction = new JButton("Preview");
            root.add(newSessionAction);
            assertEquals(WorkbenchTheme.SURFACE, root.getBackground());
            assertEquals(WorkbenchTheme.TEXT, newSessionAction.getForeground());
            assertEquals(Color.PINK, hostEditor.getBackground());
            assertSame(buttonDefault, UIManager.get("Button.background"));
            assertSame(tabDefault, UIManager.get("TabbedPaneUI"));
            int listeners = root.getContainerListeners().length;
            WorkbenchTheme.apply(root);
            assertEquals(listeners, root.getContainerListeners().length);
        });
    }
}
