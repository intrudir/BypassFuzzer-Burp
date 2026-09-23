package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.idor.IdorOptions;
import com.bypassfuzzer.burp.core.idor.IdorRunOptions;
import com.bypassfuzzer.core.scan.ResponseGuidedIdorPlanner;
import com.bypassfuzzer.core.scan.IdorPlanner;
import com.bypassfuzzer.core.scan.PairedControlSeparatorPlanner;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.List;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdorConfigureRequestEditorTest {
    @Test
    void configureShowsNativeEditorAndSearchesAsIdentifierChanges() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
            HttpRequestEditor resultsEditor = mock(HttpRequestEditor.class);
            HttpRequestEditor configEditor = mock(HttpRequestEditor.class);
            HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
            when(api.userInterface().createHttpRequestEditor()).thenReturn(resultsEditor);
            when(api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)).thenReturn(configEditor);
            when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
            when(resultsEditor.uiComponent()).thenReturn(new JPanel());
            JPanel nativeEditorComponent = new JPanel();
            when(configEditor.uiComponent()).thenReturn(nativeEditorComponent);
            when(responseEditor.uiComponent()).thenReturn(new JPanel());
            HttpRequest original = request("/namespaces/619/projects", "", "POST", "application/json", "{\"id\":\"619\"}");
            IdorPanel panel = new IdorPanel(api, original);
            try {
                assertTrue(field(panel, "selectedFamilies", Set.class)
                    .contains(ResponseGuidedIdorPlanner.FAMILY));
                assertTrue(field(panel, "selectedFamilies", Set.class)
                    .contains(PairedControlSeparatorPlanner.FAMILY));
                assertFalse(field(panel, "selectedFamilies", Set.class)
                    .contains(IdorPlanner.NUMERIC_PIVOTS_FAMILY));
                assertFalse(field(panel, "selectedFamilies", Set.class)
                    .contains(IdorPlanner.SPECIAL_IDENTIFIER_VALUES_FAMILY));
                assertFalse(field(panel, "selectedFamilies", Set.class)
                    .contains(IdorPlanner.JSON_EDGE_CASES_FAMILY));
                assertFalse(field(panel, "selectedFamilies", Set.class)
                    .contains(IdorPlanner.CANONICAL_IDENTIFIER_FORMATS_FAMILY));
                assertFalse(field(panel, "selectedFamilies", Set.class)
                    .contains(IdorPlanner.TRUNCATED_IDENTIFIER_VARIANTS_FAMILY));
                Method build = IdorPanel.class.getDeclaredMethod("buildConfigDialogContent");
                build.setAccessible(true);
                JPanel dialog = (JPanel) build.invoke(panel);
                assertSame(((BorderLayout) dialog.getLayout()).getLayoutComponent(BorderLayout.CENTER),
                    findParent(dialog, nativeEditorComponent));
                assertNotNull(((BorderLayout) dialog.getLayout()).getLayoutComponent(BorderLayout.NORTH));
                verify(configEditor).setRequest(original);
                assertFalse(containsType(dialog, javax.swing.JTabbedPane.class));

                JLabel coverageNote = field(panel, "mutationCoverageNote", JLabel.class);
                assertTrue(coverageNote.getText().contains("All applicable mutations"));
                assertTrue(coverageNote.getText().contains("may change data"));

                JTextField identifier = field(panel, "authorizedIdentifierField", JTextField.class);
                JComboBox<?> dropdown = field(panel, "locationField", JComboBox.class);
                identifier.setText("61");
                verify(configEditor).setSearchExpression("61");
                identifier.setText("619");
                verify(configEditor).setSearchExpression("619");
                JButton findLocations = findButton(dialog, "Find Locations");
                assertNotNull(findLocations);
                findLocations.doClick();

                assertEquals(2, dropdown.getItemCount());
                assertEquals(-1, dropdown.getSelectedIndex());
                dropdown.setSelectedItem("json:/id");
                assertEquals("json:/id", dropdown.getSelectedItem());
                field(panel, "targetIdentifierField", JTextField.class).setText("620");
                Method collectOptions = IdorPanel.class.getDeclaredMethod("collectOptions");
                collectOptions.setAccessible(true);
                assertEquals(com.bypassfuzzer.core.scan.IdorPlanOptions.UNLIMITED,
                    ((IdorOptions) collectOptions.invoke(panel)).maxMutations());
                var rows = panel.buildPreviewRows(new IdorOptions("619", "620",
                    new IdorRunOptions(Set.of(429, 503)), "path:2",
                    Set.of("idor.path.suffix_formats"), 1, false));
                assertEquals(3, rows.size());
                assertEquals("Control", rows.get(0).stage());
                assertEquals("Target baseline", rows.get(1).stage());
                assertEquals("620", rows.get(1).payload());
                assertEquals("/namespaces/620/projects", rows.get(1).request().path());
                var separatorRows = panel.buildPreviewRows(new IdorOptions("619", "620",
                    new IdorRunOptions(Set.of(429, 503)), "path:2",
                    Set.of(PairedControlSeparatorPlanner.FAMILY), 2, false));
                assertEquals(4, separatorRows.size());
                assertEquals("LF U+000A | id1 → id2", separatorRows.get(2).variant());
                assertEquals("/namespaces/619%0A620/projects", separatorRows.get(2).request().path());
            } catch (ReflectiveOperationException error) {
                throw new AssertionError(error);
            } finally {
                panel.cleanup();
            }
        });
    }

    @Test
    void enablingUnselectedIdentifierValuesRequiresExplicitDangerConfirmation() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
            HttpRequestEditor editor = mock(HttpRequestEditor.class);
            HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
            when(api.userInterface().createHttpRequestEditor()).thenReturn(editor);
            when(api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)).thenReturn(editor);
            when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
            when(editor.uiComponent()).thenReturn(new JPanel());
            when(responseEditor.uiComponent()).thenReturn(new JPanel());
            IdorPanel panel = new IdorPanel(api,
                request("/projects/7651/stats", "", "GET", "", ""));
            try (MockedStatic<JOptionPane> dialogs = mockStatic(JOptionPane.class)) {
                Method build = IdorPanel.class.getDeclaredMethod("buildConfigDialogContent");
                build.setAccessible(true);
                JPanel dialog = (JPanel) build.invoke(panel);
                assertTrue(field(panel, "mutationCoverageNote", JLabel.class).getText()
                    .contains("All applicable mutations"));
                JButton select = findButton(dialog, "Select Playbooks...");
                assertNotNull(select);
                java.util.concurrent.atomic.AtomicReference<String> family =
                    new java.util.concurrent.atomic.AtomicReference<>();
                dialogs.when(() -> JOptionPane.showConfirmDialog(any(), any(), anyString(), anyInt()))
                    .thenAnswer(invocation -> {
                        JScrollPane scroller = invocation.getArgument(1);
                        JCheckBox box = findFamilyCheckBox((Container) scroller.getViewport().getView(),
                            family.get());
                        assertNotNull(box);
                        assertTrue(box.getText().contains("DANGEROUS"));
                        assertFalse(box.isSelected());
                        box.setSelected(true);
                        return JOptionPane.OK_OPTION;
                    });
                for (String id : new IdorPlanner().dangerousFamilyRisks().keySet()) {
                    family.set(id);
                    dialogs.when(() -> JOptionPane.showConfirmDialog(any(), any(), anyString(),
                        anyInt(), anyInt())).thenAnswer(invocation -> {
                            assertTrue(invocation.getArgument(1, String.class).contains(family.get()));
                            return JOptionPane.NO_OPTION;
                        });
                    select.doClick();
                    assertFalse(field(panel, "selectedFamilies", Set.class).contains(id));

                    dialogs.when(() -> JOptionPane.showConfirmDialog(any(), any(), anyString(),
                        anyInt(), anyInt())).thenReturn(JOptionPane.YES_OPTION);
                    select.doClick();
                    assertTrue(field(panel, "selectedFamilies", Set.class).contains(id));
                }
            } catch (ReflectiveOperationException error) {
                throw new AssertionError(error);
            } finally { panel.cleanup(); }
        });
    }

    @Test
    void capturedJsonResponseSuppliesGenericFieldsToPreview() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
            HttpRequestEditor editor = mock(HttpRequestEditor.class);
            HttpResponseEditor responseEditor = mock(HttpResponseEditor.class);
            when(api.userInterface().createHttpRequestEditor()).thenReturn(editor);
            when(api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)).thenReturn(editor);
            when(api.userInterface().createHttpResponseEditor()).thenReturn(responseEditor);
            when(editor.uiComponent()).thenReturn(new JPanel());
            when(responseEditor.uiComponent()).thenReturn(new JPanel());
            HttpResponse captured = mock(HttpResponse.class);
            ByteArray bytes = mock(ByteArray.class);
            when(bytes.getBytes()).thenReturn("{\"organizationRef\":\"alpha\"}"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            when(captured.body()).thenReturn(bytes);
            when(captured.headers()).thenReturn(List.of());
            when(captured.statusCode()).thenReturn((short) 201);
            HttpRequest original = request("/orgs/alpha/assets", "", "POST",
                "application/json", "{\"name\":\"asset\"}");
            IdorPanel panel = new IdorPanel(api, original, captured,
                new com.bypassfuzzer.burp.core.throttle.GlobalTrafficGovernor());
            try {
                Method build = IdorPanel.class.getDeclaredMethod("buildConfigDialogContent");
                build.setAccessible(true);
                JPanel dialog = (JPanel) build.invoke(panel);
                field(panel, "authorizedIdentifierField", JTextField.class).setText("alpha");
                field(panel, "targetIdentifierField", JTextField.class).setText("beta");
                assertNotNull(findButton(dialog, "Inspect Response Fields"));
                assertTrue(field(panel, "responseFieldsLabel", JLabel.class).getText().contains("1"));
                var rows = panel.buildPreviewRows(new IdorOptions("alpha", "beta",
                    new IdorRunOptions(Set.of(429, 503)), "path:2",
                    Set.of(ResponseGuidedIdorPlanner.FAMILY), 2, false));
                assertEquals(4, rows.size());
                assertTrue(rows.stream().anyMatch(row -> row.request().bodyToString()
                    .contains("\"organizationRef\":\"beta\"")));
                assertTrue(rows.stream().anyMatch(row -> row.request().path().equals("/orgs/beta/assets")));
            } catch (ReflectiveOperationException error) {
                throw new AssertionError(error);
            } finally { panel.cleanup(); }
        });
    }

    private static <T> T field(Object target, String name, Class<T> type) throws ReflectiveOperationException {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }

    private static JButton findButton(Container parent, String label) {
        for (Component component : parent.getComponents()) {
            if (component instanceof JButton button && label.equals(button.getText())) return button;
            if (component instanceof Container child) {
                JButton match = findButton(child, label);
                if (match != null) return match;
            }
        }
        return null;
    }

    private static JCheckBox findFamilyCheckBox(Container parent, String family) {
        for (Component component : parent.getComponents()) {
            if (component instanceof JCheckBox box && family.equals(box.getActionCommand())) return box;
            if (component instanceof Container child) {
                JCheckBox match = findFamilyCheckBox(child, family);
                if (match != null) return match;
            }
        }
        return null;
    }

    private static boolean containsType(Container parent, Class<?> type) {
        for (Component component : parent.getComponents()) {
            if (type.isInstance(component)) return true;
            if (component instanceof Container child && containsType(child, type)) return true;
        }
        return false;
    }

    private static Container findParent(Container parent, Component target) {
        for (Component component : parent.getComponents()) {
            if (component == target) return parent;
            if (component instanceof Container child) {
                Container match = findParent(child, target);
                if (match != null) return match;
            }
        }
        return null;
    }
}
