package com.bypassfuzzer.burp.ui.session;

import com.bypassfuzzer.core.http.*;
import com.bypassfuzzer.core.scan.RunConfiguration;
import com.bypassfuzzer.burp.ui.WorkbenchTheme;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.awt.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class RunHeaderFieldsTest {
    @Test void removalAndUserAgentControlsFitBesideTheGrowingEditor() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var config=new RunConfiguration(Set.of(),1,1,20,Set.of(),java.util.List.of(new ConfiguredHeader("User-Agent","fixture")),Set.of("Authorization"),UserAgentMode.DISABLED,0);
            var fields=new RunHeaderFields(config);WorkbenchTheme.apply(fields);fields.setSize(710,330);layout(fields);
            for(Component component:java.util.List.of(fields.removed,fields.userAgent)) {
                Rectangle bounds=SwingUtilities.convertRectangle(component.getParent(),component.getBounds(),fields);
                assertTrue(bounds.y>=0 && bounds.y+bounds.height<=fields.getHeight(),bounds.toString());
                assertTrue(bounds.height>=20 && bounds.width>=120,bounds.toString());
            }
            JScrollPane scroll=(JScrollPane)fields.headers.getParent().getParent();
            assertTrue(scroll.getViewport().getHeight()>=120);assertEquals("User-Agent: fixture",fields.headers.getText());
            assertEquals("authorization",fields.removed.getText());
        });
    }
    private void layout(Container container){container.doLayout();for(Component c:container.getComponents())if(c instanceof Container child)layout(child);}
}
