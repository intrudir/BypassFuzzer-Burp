package com.bypassfuzzer.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.smoke.MontoyaStubs;
import com.bypassfuzzer.burp.ui.session.SessionResultsWorkspace;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.mockito.Mockito.*;

/** Offline desktop preview of the production panels. No scan traffic is sent. */
public final class WorkbenchPreview {
    private static final String[] NAMES = {"dashboard", "sweep", "bypass", "idor", "url-validation"};
    private WorkbenchPreview() { }

    public static void main(String[] args) throws Exception {
        Path output = Path.of(args.length > 0 ? args[0] : "artifacts/verification/workbench");
        Files.createDirectories(output);
        JFrame[] frame = new JFrame[1];
        BypassFuzzerTab[] root = new BypassFuzzerTab[1];
        JTabbedPane[] navigation = new JTabbedPane[1];
        MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        when(api.userInterface().createHttpRequestEditor()).thenAnswer(ignored -> requestEditor());
        when(api.userInterface().createHttpRequestEditor(any(burp.api.montoya.ui.editor.EditorOptions.class))).thenAnswer(ignored -> requestEditor());
        when(api.userInterface().createHttpResponseEditor()).thenAnswer(ignored -> responseEditor());
        HttpRequest original = request("/api/admin/users");
        try {
            SwingUtilities.invokeAndWait(() -> {
                frame[0] = new JFrame("BypassFuzzer — offline UI preview");
                frame[0].setUndecorated(true);
                when(api.userInterface().swingUtils().suiteFrame()).thenReturn(frame[0]);
                root[0] = new BypassFuzzerTab(api);
                navigation[0] = field(root[0], "tabbedPane", JTabbedPane.class);
                frame[0].setContentPane(root[0]);
                frame[0].setSize(1440, 1024);
                frame[0].setLocation(0, 0);
                frame[0].setVisible(true);
            });
            Robot robot = new Robot();
            for (int i = 2; i < 5; i++) {
                int tab = i;
                SwingUtilities.invokeAndWait(() -> navigation[0].setSelectedIndex(tab));
                settle(robot);
                capture(robot, frame[0], output.resolve(NAMES[i] + "-empty.png"));
            }
            SwingUtilities.invokeAndWait(() -> {
                for (TargetedMode mode : TargetedMode.values()) root[0].loadRequest(original, mode);
                seed(field(navigation[0].getComponentAt(1), "resultsWorkspace", SessionResultsWorkspace.class), "Sweep");
                for (int i = 2; i < 5; i++) {
                    FuzzingSessionTab session = (FuzzingSessionTab) find(navigation[0].getComponentAt(i), JTabbedPane.class).getComponentAt(0);
                    Object owner = i == 3 ? field(session, "idorPanel", Object.class)
                        : i == 4 ? field(session, "urlValidationPanel", Object.class) : session;
                    seed(field(owner, "resultsWorkspace", SessionResultsWorkspace.class), NAMES[i]);
                }
                frame[0].setContentPane(root[0]);
                frame[0].setSize(1440, 1024);
                frame[0].setLocation(0, 0);
                frame[0].setVisible(true);
            });
            for (int i = 0; i < 5; i++) {
                int tab = i;
                SwingUtilities.invokeAndWait(() -> navigation[0].setSelectedIndex(tab));
                settle(robot);
                capture(robot, frame[0], output.resolve(NAMES[i] + ".png"));
            }
            // Exercise real UI controls, including source-dependent configuration and filters.
            SwingUtilities.invokeAndWait(() -> {
                navigation[0].setSelectedIndex(1);
                Object sweep = navigation[0].getComponentAt(1);
                JComboBox<?> source = field(sweep, "modeComboBox", JComboBox.class);
                source.setSelectedIndex(1);
                if (!field(sweep, "verifyUnauthenticatedAccessCheckBox", JCheckBox.class).isVisible())
                    throw new AssertionError("Authenticated source controls hidden");
                source.setSelectedIndex(2);
                if (!field(sweep, "importMenuButton", JButton.class).isVisible())
                    throw new AssertionError("Import controls hidden");
                source.setSelectedIndex(0);
                JButton collapse = field(sweep, "configurationToggleButton", JButton.class);
                collapse.doClick();
                if (field(sweep, "configurationRail", JPanel.class).isVisible())
                    throw new AssertionError("Configuration rail did not collapse");
                collapse.doClick();
                SessionResultsWorkspace workspace = field(sweep, "resultsWorkspace", SessionResultsWorkspace.class);
                button(workspace.component(), "Filters").doClick();
            });
            settle(robot);
            capture(robot, frame[0], output.resolve("sweep-filters.png"));
            SwingUtilities.invokeAndWait(() -> {
                navigation[0].setSelectedIndex(2);
                button(root[0], "Options...").doClick();
            });
            settle(robot);
            captureWindow(robot, output.resolve("bypass-options.png"));
            closeDialogs();
            for (int tab : List.of(3, 4)) {
                SwingUtilities.invokeAndWait(() -> {
                    navigation[0].setSelectedIndex(tab);
                    button(root[0], "Configure Attack").doClick();
                });
                settle(robot);
                captureWindow(robot, output.resolve(NAMES[tab] + "-configuration.png"));
                closeDialogs();
            }
            SwingUtilities.invokeAndWait(() -> {
                navigation[0].setSelectedIndex(1);
                SessionResultsWorkspace workspace = field(navigation[0].getComponentAt(1), "resultsWorkspace", SessionResultsWorkspace.class);
                button(workspace.component(), "Hide filters").doClick();
                frame[0].setSize(1280, 800);
            });
            settle(robot);
            capture(robot, frame[0], output.resolve("sweep-1280.png"));
            Files.writeString(output.resolve("verification.txt"),
                "PASS: five-tab navigation; source modes; collapse/reopen configuration; filter drawer; Bypass options; IDOR and URL configuration dialogs; 1440x1024 and 1280x800 captures.\n"
                + "Production Swing panels; Montoya HTTP editors replaced with offline text fixtures. No traffic sent.\n");
            System.out.println("Workbench captures: " + output.toAbsolutePath());
        } finally {
            SwingUtilities.invokeAndWait(() -> {
                if (root[0] != null) root[0].cleanup();
                for (Window window : Window.getWindows()) window.dispose();
            });
        }
    }

    private static HttpRequest request(String path) {
        return MontoyaStubs.request(MontoyaStubs.httpService("api.example.test", 443, true),
            "GET " + path + " HTTP/1.1\r\nHost: api.example.test\r\nAccept: application/json\r\n\r\n");
    }

    private static void seed(SessionResultsWorkspace workspace, String mode) {
        String[] payloads = {"/..;/", "/.;/", "X-Original-URL: /admin", "/%2e/", "HEAD", "/admin.json"};
        for (int i = 0; i < payloads.length; i++) {
            String family = i == 2 ? "Header" : i == 4 ? "Verb" : "Path";
            int status = i < 3 ? 200 : 403;
            String body = status == 200 ? "{\n  \"users\": [\n    {\"id\": 1001, \"username\": \"alice\"},\n    {\"id\": 1002, \"username\": \"bob\"}\n  ]\n}" : "{\"error\": \"Forbidden\"}";
            var response = MontoyaStubs.response(("HTTP/1.1 " + status + (status == 200 ? " OK" : " Forbidden")
                + "\r\nContent-Type: application/json\r\n\r\n" + body).getBytes(StandardCharsets.UTF_8));
            String payload = payloads[i];
            String target = "GET https://api.example.test/api/admin/users";
            String metadata = status == 200 ? "403 → 200" : "";
            if (mode.equals("idor")) {
                target = i == 0 ? "Control" : i == 1 ? "Baseline" : "Mutation";
                family = i < 2 ? "idor.baseline.control" : "idor.hybrid.cross_source_conflicts";
                payload = i < 2 ? "Identifier: " + (1001 + i) : "Path identifier: 1001 → 1002";
                metadata = "";
            } else if (mode.equals("url-validation")) {
                target = "{INJECT} · body";
                family = "Absolute URL";
                metadata = "Intruder's";
                payload = i % 2 == 0 ? "https://stock.example.test@callback.example.test/"
                    : "https://callback.example.test/#stock.example.test";
            }
            workspace.addResult(new AttackResult(mode.equals("bypass") ? family : mode, payload, target,
                family, metadata, request("/api/admin/users" + payloads[i]), response));
        }
        JTable table = find(workspace.component(), JTable.class);
        // Find the results table rather than the hidden manual-filter widgets.
        table.setRowSelectionInterval(table.getRowCount() - 1, table.getRowCount() - 1);
    }

    private static JTextArea editorArea() {
        JTextArea area = new JTextArea();
        area.setFont(WorkbenchTheme.MONO);
        area.setBackground(WorkbenchTheme.EDITOR);
        area.setForeground(WorkbenchTheme.TEXT);
        area.setCaretColor(WorkbenchTheme.TEXT);
        area.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        return area;
    }
    private static HttpRequestEditor requestEditor() {
        HttpRequestEditor editor = mock(HttpRequestEditor.class);
        JTextArea area = editorArea();
        when(editor.uiComponent()).thenReturn(new JScrollPane(area));
        doAnswer(call -> { Object value = call.getArgument(0); area.setText(value == null ? "" : value.toString()); return null; })
            .when(editor).setRequest(any());
        return editor;
    }
    private static HttpResponseEditor responseEditor() {
        HttpResponseEditor editor = mock(HttpResponseEditor.class);
        JTextArea area = editorArea();
        when(editor.uiComponent()).thenReturn(new JScrollPane(area));
        doAnswer(call -> { Object value = call.getArgument(0); area.setText(value == null ? "" : value.toString()); return null; })
            .when(editor).setResponse(any());
        return editor;
    }
    private static void settle(Robot robot) { robot.waitForIdle(); robot.delay(180); }
    private static void capture(Robot robot, Window window, Path path) throws Exception {
        ImageIO.write(robot.createScreenCapture(window.getBounds()), "png", path.toFile());
    }
    private static void captureWindow(Robot robot, Path path) throws Exception {
        for (Window window : Window.getWindows()) if (window instanceof JDialog && window.isVisible()) {
            capture(robot, window, path); return;
        }
        throw new AssertionError("No visible configuration dialog");
    }
    private static void closeDialogs() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (Window window : Window.getWindows()) if (window instanceof JDialog) window.setVisible(false);
        });
    }
    private static JButton button(Component root, String text) {
        if (root instanceof JButton b && b.isShowing() && text.equals(b.getText())) return b;
        if (root instanceof Container c) for (Component child : c.getComponents()) {
            try { return button(child, text); } catch (IllegalArgumentException ignored) { }
        }
        throw new IllegalArgumentException("Missing visible button: " + text);
    }
    private static <T> T field(Object owner, String name, Class<T> type) {
        try { Field field = owner.getClass().getDeclaredField(name); field.setAccessible(true); return type.cast(field.get(owner)); }
        catch (ReflectiveOperationException e) { throw new IllegalStateException(e); }
    }
    private static <T> T find(Component root, Class<T> type) {
        if (type.isInstance(root)) return type.cast(root);
        if (root instanceof Container c) for (Component child : c.getComponents()) {
            try { return find(child, type); } catch (IllegalArgumentException ignored) { }
        }
        throw new IllegalArgumentException("Missing " + type);
    }
}
