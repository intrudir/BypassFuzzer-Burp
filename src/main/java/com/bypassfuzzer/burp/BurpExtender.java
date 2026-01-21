package com.bypassfuzzer.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.bypassfuzzer.burp.config.FuzzerConfig;
import com.bypassfuzzer.burp.ui.BypassFuzzerTab;
import com.bypassfuzzer.burp.menu.ContextMenuFactory;

/**
 * Main entry point for the BypassFuzzer Burp Suite extension.
 * Implements the Montoya API for modern Burp integration.
 */
public class BurpExtender implements BurpExtension {

    private MontoyaApi api;
    private BypassFuzzerTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // Set extension name
        api.extension().setName("BypassFuzzer");

        // Log extension loading
        api.logging().logToOutput("BypassFuzzer extension loading...");

        try {
            // Create and register main UI tab (with tabbed interface)
            mainTab = new BypassFuzzerTab(api);
            api.userInterface().registerSuiteTab("BypassFuzzer", mainTab);

            // Register context menu
            ContextMenuFactory contextMenu = new ContextMenuFactory(api, mainTab);
            api.userInterface().registerContextMenuItemsProvider(contextMenu);

            // Register unload handler
            api.extension().registerUnloadingHandler(this::cleanup);

            api.logging().logToOutput("BypassFuzzer extension loaded successfully!");

        } catch (Exception e) {
            api.logging().logToError("Failed to initialize BypassFuzzer: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Cleanup when extension is unloaded.
     */
    private void cleanup() {
        try {
            api.logging().logToOutput("BypassFuzzer extension unloading...");

            if (mainTab != null) {
                mainTab.cleanup();
            }

            api.logging().logToOutput("BypassFuzzer extension unloaded successfully");
        } catch (Exception e) {
            // Ignore errors during cleanup as API may be shutting down
        }
    }
}
