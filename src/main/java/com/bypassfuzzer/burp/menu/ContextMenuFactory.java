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

        HttpRequestResponse selected = event.messageEditorRequestResponse()
            .map(editor -> editor.requestResponse()).orElse(null);
        if (selected == null && event.selectedRequestResponses().size() == 1)
            selected = event.selectedRequestResponses().get(0);
        if (selected != null && selected.request() != null) {
            final HttpRequestResponse exchange = selected;
            JMenu sendMenu = new JMenu("Send to BypassFuzzer");
            for (TargetedMode mode : TargetedMode.values()) {
                JMenuItem modeItem = new JMenuItem(mode.title());
                modeItem.addActionListener(e -> sendToFuzzer(exchange, mode));
                sendMenu.add(modeItem);
            }
            if (exchange.response() != null && exchange.response().body() != null
                && exchange.response().body().length() > 0) {
                sendMenu.addSeparator();
                JMenuItem importSpec = new JMenuItem("Import API spec to Sweep");
                importSpec.setToolTipText("Import this captured OpenAPI/Swagger response without fetching it again.");
                importSpec.addActionListener(e -> mainTab.importApiSpec(exchange));
                sendMenu.add(importSpec);
            }
            menuItems.add(sendMenu);
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
