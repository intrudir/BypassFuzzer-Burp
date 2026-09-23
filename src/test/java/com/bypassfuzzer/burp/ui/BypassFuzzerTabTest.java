package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.update.VersionCheckResult;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.event.MouseEvent;

import org.mockito.MockedStatic;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

class BypassFuzzerTabTest {

    @Test
    void startsWithDashboardSweepAndTargetedModeTabs() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JTabbedPane tabs = findTabbedPane(tab);

        assertEquals(5, tabs.getTabCount());
        assertEquals("Dashboard", tabs.getTitleAt(0));
        assertEquals("Sweep", tabs.getTitleAt(1));
        assertEquals("Bypass", tabs.getTitleAt(2));
        assertEquals("IDOR", tabs.getTitleAt(3));
        assertEquals("URL Validation", tabs.getTitleAt(4));
    }

    @Test
    void requestSessionIsNestedUnderSelectedMode() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JTabbedPane topLevelTabs = findTabbedPane(tab);

        tab.loadRequest(request("/users/123", "", "GET", null, ""), TargetedMode.IDOR);

        JTabbedPane idorSessions = (JTabbedPane) topLevelTabs.getComponentAt(3);
        assertEquals("IDOR", topLevelTabs.getTitleAt(topLevelTabs.getSelectedIndex()));
        assertEquals(1, idorSessions.getTabCount());
        assertEquals("GET /users/123", idorSessions.getTitleAt(0));
        assertTrue(idorSessions.getComponentAt(0) instanceof FuzzingSessionTab);

        assertEquals(0, ((JTabbedPane) topLevelTabs.getComponentAt(2)).getTabCount());
        assertEquals(0, ((JTabbedPane) topLevelTabs.getComponentAt(4)).getTabCount());
    }

    @Test
    void requestTabsCanBeRenamedInEveryTargetedMode() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            BypassFuzzerTab tab = new BypassFuzzerTab(api());
            JTabbedPane topLevelTabs = findTabbedPane(tab);
            try (MockedStatic<JOptionPane> dialogs = mockStatic(JOptionPane.class)) {
                for (TargetedMode mode : TargetedMode.values()) {
                    tab.loadRequest(request("/long/path/123", "", "GET", null, ""), mode);
                    JTabbedPane sessions = (JTabbedPane) topLevelTabs.getSelectedComponent();
                    JPanel header = (JPanel) sessions.getTabComponentAt(0);
                    JLabel label = (JLabel) header.getComponent(0);
                    String newTitle = mode.title() + " account 123";
                    dialogs.when(() -> JOptionPane.showInputDialog(any(), eq("Tab name:"),
                        eq("GET /long/path/123"))).thenReturn("  " + newTitle + "  ");

                    JMenuItem rename = (JMenuItem) label.getComponentPopupMenu().getComponent(0);
                    assertEquals("Rename tab...", rename.getText());
                    rename.doClick();

                    assertEquals(newTitle, sessions.getTitleAt(0));
                    assertEquals(newTitle, label.getText());
                    assertEquals(newTitle, ((JLabel) header.getComponent(0)).getText());
                }
            }
        });
    }

    @Test
    void doubleClickRenameKeepsCurrentNameOnCancelOrBlankInput() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            BypassFuzzerTab tab = new BypassFuzzerTab(api());
            tab.loadRequest(request("/users/123", "", "GET", null, ""), TargetedMode.IDOR);
            JTabbedPane sessions = (JTabbedPane) findTabbedPane(tab).getSelectedComponent();
            JLabel label = (JLabel) ((JPanel) sessions.getTabComponentAt(0)).getComponent(0);
            try (MockedStatic<JOptionPane> dialogs = mockStatic(JOptionPane.class)) {
                dialogs.when(() -> JOptionPane.showInputDialog(any(), eq("Tab name:"),
                    eq("GET /users/123"))).thenReturn(null, "  ", "Authorized account");
                for (int attempt = 0; attempt < 3; attempt++) {
                    label.dispatchEvent(new MouseEvent(label, MouseEvent.MOUSE_CLICKED,
                        System.currentTimeMillis(), 0, 2, 2, 2, false, MouseEvent.BUTTON1));
                    assertEquals(attempt == 2 ? "Authorized account" : "GET /users/123",
                        sessions.getTitleAt(0));
                    assertEquals(sessions.getTitleAt(0), label.getText());
                }
            }
        });
    }

    @Test
    void clickingSessionHeadersSelectsTabsInEveryMode() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            BypassFuzzerTab tab = new BypassFuzzerTab(api());
            for (TargetedMode mode : TargetedMode.values()) {
                tab.loadRequest(request("/users/123", "", "GET", null, ""), mode);
                tab.loadRequest(request("/users/456", "", "GET", null, ""), mode);
                JTabbedPane sessions = (JTabbedPane) findTabbedPane(tab).getSelectedComponent();
                assertEquals(1, sessions.getSelectedIndex());

                JLabel firstTitle = (JLabel) ((JPanel) sessions.getTabComponentAt(0)).getComponent(0);
                firstTitle.dispatchEvent(new MouseEvent(firstTitle, MouseEvent.MOUSE_CLICKED,
                    System.currentTimeMillis(), 0, 2, 2, 1, false, MouseEvent.BUTTON1));
                assertEquals(0, sessions.getSelectedIndex());

                JPanel secondHeader = (JPanel) sessions.getTabComponentAt(1);
                secondHeader.dispatchEvent(new MouseEvent(secondHeader, MouseEvent.MOUSE_CLICKED,
                    System.currentTimeMillis(), 0, 2, 2, 1, false, MouseEvent.BUTTON1));
                assertEquals(1, sessions.getSelectedIndex());
            }
        });
    }

    @Test
    void dashboardStartsWithPerLaunchLimitsDisabled() {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());
        JCheckBox enabled = findNamedComponent(tab, "globalLimitsEnabled", JCheckBox.class);
        JButton pauseAll = findNamedComponent(tab, "dashboardPauseAll", JButton.class);
        JButton resumeAll = findNamedComponent(tab, "dashboardResumeAll", JButton.class);

        assertFalse(enabled.isSelected());
        assertTrue(pauseAll.isEnabled());
        assertTrue(resumeAll.isEnabled());
    }

    @Test
    void updateBannerShowsVersionDetailsAndCanBeDismissed() throws Exception {
        BypassFuzzerTab tab = new BypassFuzzerTab(api());

        SwingUtilities.invokeAndWait(() ->
            tab.showUpdateBanner(new VersionCheckResult("1.0.9", "1.0.10", true))
        );
        flushSwingEvents();

        JPanel banner = findNamedComponent(tab, "updateBanner", JPanel.class);
        JLabel message = findNamedComponent(tab, "updateBannerMessage", JLabel.class);
        JButton dismiss = findNamedComponent(tab, "updateBannerDismiss", JButton.class);

        assertTrue(banner.isVisible());
        assertTrue(message.getText().contains("BypassFuzzer 1.0.10 is available"));
        assertTrue(message.getText().contains("running 1.0.9"));
        assertTrue(message.getText().contains("bypassfuzzer.jar"));

        SwingUtilities.invokeAndWait(dismiss::doClick);
        flushSwingEvents();

        assertFalse(banner.isVisible());
    }

    private MontoyaApi api() {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        HttpRequestEditor requestEditor = mock(HttpRequestEditor.class);
        HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
        when(api.userInterface().createHttpRequestEditor()).thenReturn(requestEditor);
        when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
        when(requestEditor.uiComponent()).thenReturn(new JPanel());
        when(responseEditor.uiComponent()).thenReturn(new JPanel());
        return api;
    }

    private JTabbedPane findTabbedPane(JPanel root) {
        for (Component component : root.getComponents()) {
            if (component instanceof JTabbedPane tabs) {
                return tabs;
            }
        }
        throw new AssertionError("No top-level tabbed pane found");
    }

    private <T extends Component> T findNamedComponent(Component root, String name, Class<T> type) {
        if (type.isInstance(root) && name.equals(root.getName())) {
            return type.cast(root);
        }
        if (root instanceof Container container) {
            for (Component component : container.getComponents()) {
                try {
                    return findNamedComponent(component, name, type);
                } catch (AssertionError ignored) {
                    // Keep walking the component tree.
                }
            }
        }
        throw new AssertionError("No component named " + name + " found");
    }

    private void flushSwingEvents() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }
}
