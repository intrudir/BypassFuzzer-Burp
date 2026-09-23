package com.bypassfuzzer.burp.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.bypassfuzzer.burp.ui.BypassFuzzerTab;
import com.bypassfuzzer.burp.ui.TargetedMode;
import org.junit.jupiter.api.Test;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.List;
import java.util.Optional;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ContextMenuFactoryTest {

    @Test
    void offersEachTargetedModeAsADestination() {
        MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
        BypassFuzzerTab mainTab = mock(BypassFuzzerTab.class);
        HttpRequest targetRequest = request("/users/123", "", "GET", null, "");
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(targetRequest);

        MessageEditorHttpRequestResponse editorMessage = mock(MessageEditorHttpRequestResponse.class);
        when(editorMessage.requestResponse()).thenReturn(requestResponse);
        ContextMenuEvent event = mock(ContextMenuEvent.class);
        when(event.messageEditorRequestResponse()).thenReturn(Optional.of(editorMessage));

        List<Component> items = new ContextMenuFactory(api, mainTab).provideMenuItems(event);

        assertEquals(1, items.size());
        JMenu sendMenu = assertInstanceOf(JMenu.class, items.get(0));
        assertEquals("Send to BypassFuzzer", sendMenu.getText());
        assertEquals(3, sendMenu.getItemCount());

        for (int index = 0; index < TargetedMode.values().length; index++) {
            TargetedMode mode = TargetedMode.values()[index];
            JMenuItem modeItem = sendMenu.getItem(index);
            assertEquals(mode.title(), modeItem.getText());
            modeItem.doClick();
            verify(mainTab).loadRequest(requestResponse, mode);
        }
    }
}
