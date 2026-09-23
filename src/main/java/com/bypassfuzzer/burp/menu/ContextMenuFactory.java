package com.bypassfuzzer.burp.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.bypassfuzzer.burp.ui.BypassFuzzerTab;
import com.bypassfuzzer.burp.ui.TargetedMode;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides context menu integration for sending requests to BypassFuzzer.
 * Adds "Send to BypassFuzzer" option to right-click menus in Burp.
 */
public class ContextMenuFactory implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final BypassFuzzerTab mainTab;

    public ContextMenuFactory(MontoyaApi api, BypassFuzzerTab mainTab) {
        this.api = api;
        this.mainTab = mainTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Only show menu item if there's a selected request
        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().get()
                    .requestResponse();

            if (requestResponse != null && requestResponse.request() != null) {
                JMenu sendMenu = new JMenu("Send to BypassFuzzer");
                for (TargetedMode mode : TargetedMode.values()) {
                    JMenuItem modeItem = new JMenuItem(mode.title());
                    modeItem.addActionListener(e -> sendToFuzzer(requestResponse, mode));
                    sendMenu.add(modeItem);
                }
                menuItems.add(sendMenu);
            }
        }

        return menuItems;
    }

    private void sendToFuzzer(HttpRequestResponse requestResponse, TargetedMode mode) {
        mainTab.loadRequest(requestResponse, mode);
        api.logging().logToOutput(
            "Request sent to BypassFuzzer " + mode.title() + ": " + requestResponse.request().url()
        );
    }
}
