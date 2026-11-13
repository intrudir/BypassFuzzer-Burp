package com.bypassfuzzer.burp.ui.session;

import javax.swing.SwingUtilities;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;

/** Makes each completed header click sort, including quick repeated clicks. */
final class ResultsTableHeader extends JTableHeader {
    ResultsTableHeader(TableColumnModel columns) {
        super(columns);
    }

    @Override protected void processMouseEvent(MouseEvent event) {
        MouseEvent dispatched = event;
        if (event.getID() == MouseEvent.MOUSE_CLICKED && event.getClickCount() > 1
            && !event.isConsumed() && SwingUtilities.isLeftMouseButton(event)) {
            int column = columnAtPoint(event.getPoint());
            if (column >= 0) {
                Rectangle interior = getHeaderRect(column);
                // Keep native double-click auto-size at column dividers (the UI's 3px resize zone).
                interior.grow(-3, 0);
                if (interior.contains(event.getPoint())) {
                    // BasicTableHeaderUI otherwise ignores even-numbered clicks.
                    dispatched = new MouseEvent(this, event.getID(), event.getWhen(), event.getModifiersEx(),
                        event.getX(), event.getY(), event.getXOnScreen(), event.getYOnScreen(),
                        1, event.isPopupTrigger(), event.getButton());
                }
            }
        }
        super.processMouseEvent(dispatched);
        if (dispatched.isConsumed()) event.consume();
    }
}
