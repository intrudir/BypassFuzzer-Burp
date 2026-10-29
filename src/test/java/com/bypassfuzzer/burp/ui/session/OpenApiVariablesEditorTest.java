package com.bypassfuzzer.burp.ui.session;

import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JTextArea;
import java.awt.Component;
import java.awt.Container;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OpenApiVariablesEditorTest {
    @Test
    void listsSpecNamesBlankAndKeepsExistingAndCustomValues() {
        var editor = new OpenApiVariablesEditor(Map.of("tenantId", "live", "custom", "keep"),
            Map.of("tenantId", "example", "region", "US", "count", "1"));
        assertEquals(Map.of("tenantId", "live", "custom", "keep", "region", "", "count", ""), editor.variables());
    }

    @Test
    void fillUsesCurrentEditsAndOnlyChangesEmptyEntries() {
        var editor = new OpenApiVariablesEditor(Map.of(),
            Map.of("tenantId", "example", "region", "US", "count", "1", "conflict", ""));
        find(editor, JTextArea.class).setText("tenantId=typed-live-value\nregion=\ncount=\ncustom=a=b\nconflict=\n");
        fillButton(editor).doClick();
        assertEquals(Map.of("tenantId", "typed-live-value", "region", "US", "count", "1",
            "custom", "a=b", "conflict", ""), editor.variables());
        fillButton(editor).doClick();
        assertEquals("typed-live-value", editor.variables().get("tenantId"));
    }

    @Test
    void editsRemainLocalAndInvalidInputIsNotDiscardedByFill() {
        var current = Map.of("tenantId", "live");
        var editor = new OpenApiVariablesEditor(current, Map.of("tenantId", "example"));
        var text = find(editor, JTextArea.class);
        text.setText("unfinished line");
        fillButton(editor).doClick();
        assertEquals("unfinished line", text.getText());
        assertThrows(IllegalArgumentException.class, editor::variables);
        assertEquals(Map.of("tenantId", "live"), current);
    }

    static JButton fillButton(Container parent) {
        for (Component child : parent.getComponents()) {
            if (child instanceof JButton button && "Fill empty with examples".equals(button.getText())) return button;
            if (child instanceof Container nested) {
                JButton found = fillButton(nested);
                if (found != null) return found;
            }
        }
        return null;
    }

    static <T extends Component> T find(Container parent, Class<T> type) {
        for (Component child : parent.getComponents()) {
            if (type.isInstance(child)) return type.cast(child);
            if (child instanceof Container nested) {
                T found = find(nested, type);
                if (found != null) return found;
            }
        }
        return null;
    }
}
