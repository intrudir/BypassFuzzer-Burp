package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepCandidate;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepEngine;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepOptions;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPayloadSet;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepProbe;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepProbeGenerator;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepPreview;
import com.bypassfuzzer.burp.http.UserAgentMode;
import com.bypassfuzzer.burp.http.ConfiguredHeader;
import com.bypassfuzzer.burp.core.throttle.ThrottleSettings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.JTable;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Container;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.request;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.requestWithHeaders;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CoverageSweepPanelTest {

    @TempDir
    Path tempDir;

    @Test
    void doublePortHostSweepProbesAreEnabledByDefault() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        HostPortsControl hostPorts = field(panel, "hostPortsControl", HostPortsControl.class);
        CoverageSweepFamilyControl families = field(
            panel, "payloadFamilyControl", CoverageSweepFamilyControl.class);
        JCheckBox enableCheckbox = field(hostPorts, "enableCheckbox", JCheckBox.class);
        Method buildDialog = CoverageSweepFamilyControl.class.getDeclaredMethod("buildDialogContent");
        buildDialog.setAccessible(true);
        JPanel payloadFamiliesDialog = (JPanel) buildDialog.invoke(families);

        assertTrue(enableCheckbox.isSelected());
        assertEquals(List.of(0), currentOptions(panel).hostPortProbePorts());
        assertTrue(currentOptions(panel).hostPortProbesEnabled());
        assertTrue(SwingUtilities.isDescendingFrom(enableCheckbox, payloadFamiliesDialog));
        families.setHighSignalFamilyEnabled("Host Parsing", false);
        assertFalse(enableCheckbox.isEnabled());
        families.setHighSignalFamilyEnabled("Host Parsing", true);
        assertTrue(enableCheckbox.isEnabled());

        enableCheckbox.doClick();

        assertFalse(currentOptions(panel).hostPortProbesEnabled());
    }

    @Test
    void sweepCollectsItsOwnRequestHeaders() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        field(panel, "browserUserAgentCheckBox", JCheckBox.class).setSelected(false);
        RequestHeadersControl control = field(panel, "requestHeadersControl", RequestHeadersControl.class);
        control.setHeaders(List.of(new ConfiguredHeader("X-Tenant", "blue")));

        assertEquals(List.of(new ConfiguredHeader("X-Tenant", "blue")),
            currentOptions(panel).requestHeaders());
    }

    @Test
    void browserUserAgentPresetIsOnByDefaultAndInjectsAUserAgent() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));

        assertTrue(field(panel, "browserUserAgentCheckBox", JCheckBox.class).isSelected());
        List<ConfiguredHeader> headers = currentOptions(panel).requestHeaders();
        assertEquals(1, headers.size());
        assertTrue(headers.get(0).name().equalsIgnoreCase("User-Agent"));
        assertTrue(headers.get(0).value().contains("Chrome/"),
            "expected a browser UA, got " + headers.get(0).value());
    }

    @Test
    void browserUserAgentPresetDoesNotOverrideAUserSuppliedUserAgent() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        RequestHeadersControl control = field(panel, "requestHeadersControl", RequestHeadersControl.class);
        control.setHeaders(List.of(new ConfiguredHeader("User-Agent", "my-scanner/1.0")));

        List<ConfiguredHeader> headers = currentOptions(panel).requestHeaders();
        assertEquals(List.of(new ConfiguredHeader("User-Agent", "my-scanner/1.0")), headers);
    }

    @Test
    void requestHeadersMenuOffersSyntheticAndBrowserLikeUserAgentRandomization() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        RequestHeadersControl control = field(panel, "requestHeadersControl", RequestHeadersControl.class);
        JCheckBox randomize = field(
            control, "userAgentRandomizationCheckBox", JCheckBox.class);
        JComboBox<?> style = field(control, "userAgentStyleComboBox", JComboBox.class);
        JCheckBox browserPreset = field(panel, "browserUserAgentCheckBox", JCheckBox.class);
        Method buildUserAgentPanel = RequestHeadersControl.class.getDeclaredMethod("buildUserAgentPanel");
        buildUserAgentPanel.setAccessible(true);
        JPanel userAgentPanel = (JPanel) buildUserAgentPanel.invoke(control);

        assertEquals("Randomize User-Agent for every request", randomize.getText());
        assertTrue(SwingUtilities.isDescendingFrom(randomize, userAgentPanel));
        assertTrue(SwingUtilities.isDescendingFrom(style, userAgentPanel));
        assertFalse(randomize.isSelected());
        assertEquals("Synthetic tokens (recommended)", style.getItemAt(0));
        assertEquals("Browser-like variants", style.getItemAt(1));
        assertEquals(UserAgentMode.DISABLED, currentOptions(panel).userAgentMode());
        assertTrue(browserPreset.isEnabled());

        control.setUserAgentMode(UserAgentMode.SYNTHETIC);

        assertEquals(UserAgentMode.SYNTHETIC, currentOptions(panel).userAgentMode());
        assertTrue(currentOptions(panel).requestHeaders().isEmpty(),
            "the fixed browser preset must not be added when randomization is active");
        assertTrue(browserPreset.isSelected(), "the preset selection should be preserved");
        assertFalse(browserPreset.isEnabled(), "the overridden preset should be visibly inactive");
        assertTrue(control.button().getText().contains("UA synthetic"));

        control.setUserAgentMode(UserAgentMode.BROWSER_LIKE);
        assertEquals(UserAgentMode.BROWSER_LIKE, currentOptions(panel).userAgentMode());
        assertTrue(control.button().getText().contains("UA browser-like"));

        control.setUserAgentMode(UserAgentMode.DISABLED);
        assertTrue(browserPreset.isEnabled());
        assertTrue(currentOptions(panel).requestHeaders().get(0).value().contains("Chrome/"));
    }

    @Test
    void userAgentRandomizationOverridesFixedHeaderAtEngineBoundary() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        RequestHeadersControl control = field(panel, "requestHeadersControl", RequestHeadersControl.class);
        control.setHeaders(List.of(new ConfiguredHeader("User-Agent", "fixed-agent")));
        control.setUserAgentMode(UserAgentMode.SYNTHETIC);
        CoverageSweepOptions panelOptions = currentOptions(panel);
        CoverageSweepOptions options = new CoverageSweepOptions(
            panelOptions.statuses(), panelOptions.inScopeOnly(), panelOptions.maxCandidates(), 8,
            panelOptions.concurrency(), panelOptions.perHostConcurrency(), panelOptions.throttleStatusCodes(),
            panelOptions.mode(), panelOptions.authSelection(), panelOptions.excludeStaticAssets(),
            panelOptions.verifyUnauthenticatedAccess(), panelOptions.hostPortProbePorts(),
            panelOptions.requestHeaders(), panelOptions.payloadSet(), panelOptions.posture(),
            panelOptions.familySelection(), panelOptions.pauseMode(), panelOptions.fixedPauseMillis(),
            panelOptions.userAgentMode(), panelOptions.userAgentRandomizationSeed());
        CoverageSweepEngine engine = new CoverageSweepEngine(api(List.of()));
        HttpRequest original = requestWithHeaders("/admin", "", "GET",
            Map.of("User-Agent", "captured-agent"), "");

        List<CoverageSweepProbe> firstPreview = engine.buildProbes(candidate(original, 403), options);
        List<CoverageSweepProbe> secondPreview = engine.buildProbes(candidate(original, 403), options);
        List<String> firstValues = firstPreview.stream()
            .map(probe -> probe.request().headerValue("User-Agent")).toList();
        List<String> secondValues = secondPreview.stream()
            .map(probe -> probe.request().headerValue("User-Agent")).toList();

        assertEquals(firstValues, secondValues, "the exact preview must be stable for one Sweep run");
        assertTrue(firstValues.stream().allMatch(value -> value.startsWith("vexa-")), firstValues.toString());
        assertTrue(firstValues.stream().noneMatch("fixed-agent"::equals));
        assertTrue(firstValues.stream().distinct().count() > 1,
            "distinct generated requests should not share one User-Agent");
    }

    @Test
    void throttlePostureDefaultsToRideHardAndTogglesToCautious() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        ThrottleSettingsControl throttle = field(panel, "throttleControl", ThrottleSettingsControl.class);
        JCheckBox rideHard = field(throttle, "rideHardCheckbox", JCheckBox.class);

        assertTrue(rideHard.isSelected());
        assertEquals(com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.RIDE_HARD,
            currentOptions(panel).throttlePosture());

        rideHard.setSelected(false);

        assertEquals(com.bypassfuzzer.burp.core.throttle.ThrottleSettings.Posture.CONSERVATIVE,
            currentOptions(panel).throttlePosture());
    }

    @Test
    void browserUserAgentPresetCanBeDisabled() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        field(panel, "browserUserAgentCheckBox", JCheckBox.class).setSelected(false);

        assertTrue(currentOptions(panel).requestHeaders().isEmpty());
    }

    @Test
    void payloadSetDefaultsToHighSignalAndCanSelectAllPayloads() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403))));
        JComboBox<?> payloadSet = field(panel, "payloadSetComboBox", JComboBox.class);
        JLabel estimate = field(panel, "estimateLabel", JLabel.class);
        button(panel, "loadButton").doClick();

        assertEquals(2, payloadSet.getItemCount());
        assertEquals("High signal", payloadSet.getSelectedItem());
        assertEquals(CoverageSweepPayloadSet.HIGH_SIGNAL, currentOptions(panel).payloadSet());
        assertTrue(estimate.getText().contains("configuration ceiling"));
        assertTrue(estimate.getText().contains("Exact generated count"));

        payloadSet.setSelectedIndex(1);

        assertEquals(CoverageSweepPayloadSet.ALL_PAYLOADS, currentOptions(panel).payloadSet());
        assertTrue(estimate.getText().contains("Bypass payload families enabled"));
    }

    @Test
    void sweepThrottleSupportsFixedAndSmartGlobalPauses() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        ThrottleSettingsControl throttle = field(panel, "throttleControl", ThrottleSettingsControl.class);
        JComboBox<?> pauseMode = field(throttle, "pauseModeComboBox", JComboBox.class);
        JTextField fixedSeconds = field(throttle, "fixedPauseSecondsField", JTextField.class);

        assertEquals("No global pause (adaptive)", pauseMode.getSelectedItem());
        assertEquals(ThrottleSettings.PauseMode.OFF, currentOptions(panel).pauseMode());

        pauseMode.setSelectedIndex(1);
        fixedSeconds.setText("45");
        assertEquals(ThrottleSettings.PauseMode.FIXED, currentOptions(panel).pauseMode());
        assertEquals(45_000L, currentOptions(panel).fixedPauseMillis());

        pauseMode.setSelectedIndex(2);
        assertEquals(ThrottleSettings.PauseMode.SMART, currentOptions(panel).pauseMode());
    }

    @Test
    void payloadFamiliesCanBeControlledIndependentlyForBothSweepInventories() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        CoverageSweepFamilyControl control = field(
            panel, "payloadFamilyControl", CoverageSweepFamilyControl.class);

        assertTrue(control.button().isVisible());
        control.setHighSignalFamilyEnabled("Header", false);
        assertFalse(currentOptions(panel).familySelection().highSignalFamilies().contains("Header"));

        field(panel, "payloadSetComboBox", JComboBox.class).setSelectedIndex(1);
        control.setBypassFamilyEnabled(
            com.bypassfuzzer.burp.core.attacks.AttackType.HEADER, false);
        assertFalse(currentOptions(panel).familySelection().bypassFamilies().contains(
            com.bypassfuzzer.burp.core.attacks.AttackType.HEADER));
        assertTrue(currentOptions(panel).familySelection().bypassFamilies().contains(
            com.bypassfuzzer.burp.core.attacks.AttackType.PATH));
    }

    @Test
    void importedEndpointDedupeIsOffByDefault() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));

        assertFalse(checkbox(panel, "dedupeImportedEndpointsCheckBox").isSelected());
    }

    @Test
    void authenticatedModePassivelyFiltersBySelectedIdentifiersAndSafeMethods() throws Exception {
        HttpRequest get = requestWithHeaders("/account", "", "GET",
            Map.of("Cookie", "theme=dark; JSESSIONID=secret"), "");
        HttpRequest post = requestWithHeaders("/update", "", "POST",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history(get, 200), history(post, 200))));
        JComboBox<?> mode = field(panel, "modeComboBox", JComboBox.class);

        mode.setSelectedIndex(1);
        assertFalse(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertFalse(checkbox(panel, "status401CheckBox").isVisible());
        assertFalse(checkbox(panel, "status403CheckBox").isVisible());
        assertFalse(checkbox(panel, "status3xxCheckBox").isVisible());
        assertFalse(checkbox(panel, "status4xxCheckBox").isVisible());
        button(panel, "loadButton").doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/account", table.getValueAt(0, 3));
        assertFalse(button(panel, "importButton").isEnabled());
        assertFalse(button(panel, "importButton").isVisible());
        assertTrue(button(panel, "loadButton").isVisible());

        checkbox(panel, "includeUnsafeMethodsCheckBox").doClick();
        assertEquals(2, table.getRowCount());

        mode.setSelectedIndex(0);
        assertTrue(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertTrue(checkbox(panel, "status401CheckBox").isVisible());
        assertTrue(checkbox(panel, "status403CheckBox").isVisible());
        assertTrue(checkbox(panel, "status3xxCheckBox").isVisible());
        assertTrue(checkbox(panel, "status4xxCheckBox").isVisible());
    }

    @Test
    void authenticatedHistoryCollectionRunsOffTheSwingEventThread() throws Exception {
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        AtomicBoolean collectedOnEventThread = new AtomicBoolean(true);
        CountDownLatch collectionStarted = new CountDownLatch(1);
        when(engine.collectPreview(any(CoverageSweepOptions.class))).thenAnswer(invocation -> {
            collectedOnEventThread.set(SwingUtilities.isEventDispatchThread());
            collectionStarted.countDown();
            return new CoverageSweepPreview(0, 0, List.of());
        });
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);

        SwingUtilities.invokeAndWait(() -> {
            fieldUnchecked(panel, "modeComboBox", JComboBox.class).setSelectedIndex(1);
            fieldUnchecked(panel, "loadButton", JButton.class).doClick();
        });

        assertTrue(collectionStarted.await(2, TimeUnit.SECONDS));
        assertFalse(collectedOnEventThread.get());
        for (int i = 0; i < 50
            && field(panel, "candidateLoadWorker", javax.swing.SwingWorker.class) != null; i++) {
            Thread.sleep(20);
            SwingUtilities.invokeAndWait(() -> { });
        }
        panel.cleanup();
    }

    @Test
    void modeSelectorShowsOnlyTheRelevantSourceControls() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        JComboBox<?> mode = field(panel, "modeComboBox", JComboBox.class);
        JButton load = button(panel, "loadButton");
        JButton importTargets = button(panel, "importButton");
        JButton importMenu = button(panel, "importMenuButton");
        JButton clearImport = button(panel, "clearImportButton");
        JButton applyBaseUrl = button(panel, "applyOpenApiBaseUrlButton");
        JButton authIdentifiers = button(panel, "authIdentifiersButton");
        JButton requestHeaders = field(panel, "requestHeadersControl", RequestHeadersControl.class).button();
        JButton throttle = field(panel, "throttleControl", ThrottleSettingsControl.class).button();
        JComboBox<?> payloadSet = field(panel, "payloadSetComboBox", JComboBox.class);

        assertEquals(3, mode.getItemCount());
        assertTrue(payloadSet.isVisible());
        assertSame(requestHeaders.getParent(), authIdentifiers.getParent());
        assertNotSame(requestHeaders.getParent(), throttle.getParent());
        assertTrue(requestHeaders.isVisible());
        assertFalse(authIdentifiers.isVisible());
        assertTrue(load.isVisible());
        assertFalse(importTargets.isVisible());
        assertFalse(importMenu.isVisible());
        assertFalse(clearImport.isVisible());
        assertFalse(applyBaseUrl.isVisible());
        assertTrue(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertSame(load, firstVisibleComponent(load.getParent()));

        mode.setSelectedIndex(1);

        assertTrue(payloadSet.isVisible());
        assertTrue(requestHeaders.isVisible());
        assertTrue(authIdentifiers.isVisible());
        assertTrue(load.isVisible());
        assertFalse(importTargets.isVisible());
        assertFalse(importMenu.isVisible());
        assertFalse(clearImport.isVisible());
        assertFalse(applyBaseUrl.isVisible());
        assertFalse(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertSame(load, firstVisibleComponent(load.getParent()));

        mode.setSelectedIndex(2);

        assertTrue(payloadSet.isVisible());
        assertTrue(requestHeaders.isVisible());
        assertFalse(authIdentifiers.isVisible());
        assertFalse(load.isVisible());
        assertTrue(importTargets.isVisible());
        assertTrue(importTargets.isEnabled());
        assertTrue(importMenu.isVisible());
        assertTrue(importMenu.isEnabled());
        assertTrue(clearImport.isVisible());
        assertFalse(clearImport.isEnabled());
        assertTrue(applyBaseUrl.isVisible());
        assertFalse(applyBaseUrl.isEnabled());
        assertFalse(field(panel, "pullResponsesLabel", javax.swing.JLabel.class).isVisible());
        assertFalse(checkbox(panel, "status401CheckBox").isVisible());
        assertFalse(checkbox(panel, "status403CheckBox").isVisible());
        assertFalse(checkbox(panel, "status3xxCheckBox").isVisible());
        assertFalse(checkbox(panel, "status4xxCheckBox").isVisible());
    }

    @Test
    void authenticatedModeOffersAnonymousVerification() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        JComboBox<?> mode = field(panel, "modeComboBox", JComboBox.class);
        JCheckBox verify = checkbox(panel, "verifyUnauthenticatedAccessCheckBox");
        SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
        SessionResultsPanel resultsPanel = field(workspace, "resultsPanel", SessionResultsPanel.class);
        javax.swing.JTabbedPane viewerTabs = field(resultsPanel, "viewerTabs", javax.swing.JTabbedPane.class);

        assertTrue(verify.isSelected());
        assertFalse(verify.isVisible());
        assertEquals(4, viewerTabs.getTabCount());

        mode.setSelectedIndex(1);
        assertTrue(verify.isVisible());
        assertEquals(6, viewerTabs.getTabCount());

        mode.setSelectedIndex(0);
        assertEquals(4, viewerTabs.getTabCount());
    }

    @Test
    void browserUserAgentSitsBesideStateChangingMethodsAndSweepUsesSharedRetryRow() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        JCheckBox browser = checkbox(panel, "browserUserAgentCheckBox");
        JCheckBox unsafe = checkbox(panel, "includeUnsafeMethodsCheckBox");
        SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
        JPanel retryRow = field(workspace, "retryRow", JPanel.class);

        assertSame(unsafe.getParent(), browser.getParent());
        assertTrue(retryRow.isVisible());
        assertTrue(field(workspace, "retryQueueButton", JButton.class).getText().startsWith("Retry queue"));
        assertEquals("Pause", button(panel, "pauseButton").getText());
        assertFalse(button(panel, "pauseButton").isEnabled());
    }

    @Test
    void retryQueueButtonsAlwaysUseTheSameVisibleQueueCount() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
        JButton queueButton = field(workspace, "retryQueueButton", JButton.class);
        JButton retryButton = workspace.retryThrottledButton();
        HttpRequest throttledRequest = request("/limited", "", "GET", null, "");

        workspace.addResult(new AttackResult(
            "Coverage Sweep", "header probe", "GET /limited", "Header", "",
            throttledRequest, response(429, "text/plain", "slow down")));
        SwingUtilities.invokeAndWait(() -> { });

        assertEquals("Retry queue (1)", queueButton.getText());
        assertEquals("Retry Queued (1)", retryButton.getText());
        assertEquals(1, workspace.throttledRetrySnapshot().size());

        workspace.clear();
        SwingUtilities.invokeAndWait(() -> { });

        assertEquals("Retry queue (0)", queueButton.getText());
        assertEquals("Retry Queued (0)", retryButton.getText());
    }

    @Test
    void authenticatedModeExcludesStaticAssetsByDefaultAndCheckboxIncludesThem() throws Exception {
        HttpRequest account = requestWithHeaders("/account", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest script = requestWithHeaders("/static/app.js?v=1", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest image = requestWithHeaders("/avatar", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest stylesheet = requestWithHeaders("/static/site.css", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        HttpRequest font = requestWithHeaders("/static/inter.woff", "", "GET",
            Map.of("Authorization", "Bearer secret"), "");
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history(account, 200, "application/json"),
            history(script, 200, "text/plain"),
            history(image, 200, "image/webp"),
            history(stylesheet, 200, "text/plain"),
            history(font, 200, "application/octet-stream")
        )));

        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(1);
        JCheckBox excludeStatic = checkbox(panel, "excludeStaticAssetsCheckBox");
        assertTrue(excludeStatic.isSelected());

        button(panel, "loadButton").doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/account", table.getValueAt(0, 3));

        excludeStatic.doClick();
        button(panel, "loadButton").doClick();

        assertEquals(5, table.getRowCount());
    }

    @Test
    void previewTableUpdatesAfterLoadingProxyHistory() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403))));

        button(panel, "loadButton").doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/blocked", table.getValueAt(0, 3));
        assertTrue(button(panel, "startButton").isEnabled());
    }

    @Test
    void candidateTableColumnsAreSortable() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history("/z-last", 403),
            history("/a-first", 403)
        )));
        button(panel, "loadButton").doClick();
        JTable table = field(panel, "candidateTable", JTable.class);

        assertTrue(table.getRowSorter() != null);
        table.getRowSorter().toggleSortOrder(3);
        assertEquals("/a-first", table.getValueAt(0, 3));
        assertEquals("/z-last", table.getValueAt(1, 3));

        table.getRowSorter().toggleSortOrder(3);
        assertEquals("/z-last", table.getValueAt(0, 3));
        assertEquals("/a-first", table.getValueAt(1, 3));
    }

    @Test
    void responseStatusCheckboxesControlLoadedHistory() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history("/redirect", 302),
            history("/blocked", 403),
            history("/missing", 404)
        )));
        JTable table = field(panel, "candidateTable", JTable.class);

        button(panel, "loadButton").doClick();

        assertEquals(1, table.getRowCount());
        assertEquals("/blocked", table.getValueAt(0, 3));

        checkbox(panel, "status3xxCheckBox").setSelected(true);
        checkbox(panel, "status4xxCheckBox").setSelected(true);
        button(panel, "loadButton").doClick();

        assertEquals(3, table.getRowCount());
    }

    @Test
    void importsTargetUrlsFromTextFileIntoPreviewTable() throws Exception {
        Path targets = tempDir.resolve("sweep-targets.txt");
        Files.writeString(targets, String.join(System.lineSeparator(),
            "https://victim.example/admin/users",
            "https://victim.example/admin/info",
            "# ignored comment",
            "not-a-url"
        ));
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(2, 2, List.of(
            candidate("https://victim.example/admin/users", "/admin/users"),
            candidate("https://victim.example/admin/info", "/admin/info")
        ));
        when(engine.collectPreviewFromUrls(anyList(), any(CoverageSweepOptions.class), eq(false)))
            .thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);
        JTable table = field(panel, "candidateTable", JTable.class);

        assertTrue(panel.importTargetsFromFile(targets));

        assertEquals(2, table.getRowCount());
        assertTrue(button(panel, "startButton").isEnabled());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());
        assertTrue(button(panel, "previewProbesButton").isEnabled());
        assertEquals("GET", table.getValueAt(0, 1));
        assertEquals("Imported", table.getValueAt(0, 4));
        assertTrue(
            "/admin/info".equals(table.getValueAt(0, 3))
                || "/admin/users".equals(table.getValueAt(0, 3))
        );
        assertEquals(0, field(panel, "resultsWorkspace", SessionResultsWorkspace.class).allResultsCount());
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("dedupe off"));
    }

    @Test
    void importsRetryQueueJsonEntriesAsRegularSweepCandidates() throws Exception {
        Path retryPackage = tempDir.resolve("bypassfuzzer-retry-queue.json");
        Files.writeString(retryPackage, """
            {
              "version": "1",
              "type": "bypassfuzzer-retry-queue",
              "entries": [
                {"url": "https://dev.example.test/api/docs/.bak", "method": "GET"},
                {"url": "https://dev.example.test/api/docs/.old", "method": "GET"}
              ]
            }
            """);
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(2, 2, List.of(
            candidate("https://dev.example.test/api/docs/.bak", "/api/docs/.bak"),
            candidate("https://dev.example.test/api/docs/.old", "/api/docs/.old")
        ));
        when(engine.collectPreviewFromUrls(eq(List.of(
            "https://dev.example.test/api/docs/.bak",
            "https://dev.example.test/api/docs/.old"
        )), any(CoverageSweepOptions.class), eq(false))).thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);

        assertTrue(panel.importTargetsFromFile(retryPackage));

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(2, table.getRowCount());
        assertEquals("/api/docs/.bak", table.getValueAt(0, 3));
        assertEquals("/api/docs/.old", table.getValueAt(1, 3));
        assertTrue(button(panel, "startButton").isEnabled());
        assertTrue(field(panel, "statusLabel", JLabel.class).getText()
            .contains("retry-package request(s) as Sweep candidates"));
        verify(engine).collectPreviewFromUrls(eq(List.of(
            "https://dev.example.test/api/docs/.bak",
            "https://dev.example.test/api/docs/.old"
        )), any(CoverageSweepOptions.class), eq(false));
    }

    @Test
    void visibleImportFileChooserAcceptsTextAndRetryJsonFiles() {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));

        assertTrue(panel.targetImportFileFilter().accept(
            tempDir.resolve("targets.txt").toFile()));
        assertTrue(panel.targetImportFileFilter().accept(
            tempDir.resolve("bypassfuzzer-retry-queue.json").toFile()));
        assertFalse(panel.targetImportFileFilter().accept(
            tempDir.resolve("targets.csv").toFile()));
    }

    @Test
    void clearImportRemovesCandidatesAndBaseUrlForFreshStart() throws Exception {
        Path targets = tempDir.resolve("sweep-targets.txt");
        Files.writeString(targets, "https://victim.example/admin/users\n");
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://victim.example/admin/users", "/admin/users")
        ));
        when(engine.collectPreviewFromUrls(anyList(), any(CoverageSweepOptions.class), eq(false)))
            .thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);
        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(2);
        JTextField baseUrl = field(panel, "openApiBaseUrlField", JTextField.class);
        baseUrl.setText("https://api.example.test/v1");

        assertTrue(panel.importTargetsFromFile(targets));
        assertEquals(1, field(panel, "candidateTable", JTable.class).getRowCount());
        assertTrue(button(panel, "clearImportButton").isEnabled());

        button(panel, "clearImportButton").doClick();

        assertEquals(0, field(panel, "candidateTable", JTable.class).getRowCount());
        assertEquals("", baseUrl.getText());
        assertFalse(button(panel, "startButton").isEnabled());
        assertFalse(button(panel, "viewCandidateButton").isEnabled());
        assertFalse(button(panel, "previewProbesButton").isEnabled());
        assertFalse(button(panel, "clearImportButton").isEnabled());
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("cleared"));
    }

    @Test
    void importsOpenApiYamlThroughImportMode() throws Exception {
        Path spec = tempDir.resolve("openapi.yaml");
        Files.writeString(spec, "openapi: 3.0.0\npaths: {}\n");
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://api.example.test/users", "/users")
        ));
        when(engine.collectPreviewFromOpenApi(anyString(), anyString(), anyString(), eq(""),
            any(CoverageSweepOptions.class), eq(false)))
            .thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);

        assertTrue(panel.importTargetsFromFile(spec));

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/users", table.getValueAt(0, 3));
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("OpenAPI operation"));
    }

    @Test
    void importsPostmanCollectionThroughImportMode() throws Exception {
        Path collection = tempDir.resolve("example.postman_collection.json");
        String source = """
            {"info":{"schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
             "item":[{"request":{"method":"POST","url":"https://api.example.test/users"}}]}
            """;
        Files.writeString(collection, source);
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://api.example.test/users", "/users")
        ));
        when(engine.collectPreviewFromPostman(eq(source), eq(""),
            any(CoverageSweepOptions.class), eq(false))).thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);

        assertTrue(panel.importTargetsFromFile(collection));

        assertEquals(1, field(panel, "candidateTable", JTable.class).getRowCount());
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("Postman request"));
        verify(engine).collectPreviewFromPostman(eq(source), eq(""),
            any(CoverageSweepOptions.class), eq(false));
    }

    @Test
    void appliesBaseUrlToAlreadyImportedOpenApiDocument() throws Exception {
        Path spec = tempDir.resolve("openapi.yaml");
        String source = "openapi: 3.0.0\npaths: {}\n";
        Files.writeString(spec, source);
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview originalPreview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://localhost/users", "/users")));
        CoverageSweepPreview rebasedPreview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://api.example.test/v2/users", "/v2/users")));
        when(engine.collectPreviewFromOpenApi(eq(source), eq("openapi.yaml"), eq(""), eq(""),
            any(CoverageSweepOptions.class), eq(false)))
            .thenReturn(originalPreview);
        when(engine.collectPreviewFromOpenApi(eq(source), eq("openapi.yaml"),
            eq("https://api.example.test/v2"), eq(""), any(CoverageSweepOptions.class), eq(false)))
            .thenReturn(rebasedPreview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);
        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(2);

        assertTrue(panel.importTargetsFromFile(spec));
        JButton apply = button(panel, "applyOpenApiBaseUrlButton");
        assertTrue(apply.isEnabled());
        field(panel, "openApiBaseUrlField", JTextField.class)
            .setText("https://api.example.test/v2");

        apply.doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/v2/users", table.getValueAt(0, 3));
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("Applied OpenAPI base URL"));
        verify(engine).collectPreviewFromOpenApi(eq(source), eq("openapi.yaml"),
            eq("https://api.example.test/v2"), eq(""), any(CoverageSweepOptions.class), eq(false));
    }

    @Test
    void invalidBaseUrlDoesNotDiscardExistingImportedTargets() throws Exception {
        Path spec = tempDir.resolve("openapi.json");
        String source = "{\"openapi\":\"3.0.0\",\"paths\":{}}";
        Files.writeString(spec, source);
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview originalPreview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://localhost/users", "/users")));
        when(engine.collectPreviewFromOpenApi(eq(source), eq("openapi.json"), eq(""), eq(""),
            any(CoverageSweepOptions.class), eq(false))).thenReturn(originalPreview);
        when(engine.collectPreviewFromOpenApi(eq(source), eq("openapi.json"), eq("not-a-url"),
            eq(""), any(CoverageSweepOptions.class), eq(false))).thenThrow(
                new IllegalArgumentException("OpenAPI base URL must be an absolute HTTP or HTTPS URL"));
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);
        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(2);
        assertTrue(panel.importTargetsFromFile(spec));
        field(panel, "openApiBaseUrlField", JTextField.class).setText("not-a-url");

        button(panel, "applyOpenApiBaseUrlButton").doClick();

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/users", table.getValueAt(0, 3));
        assertTrue(button(panel, "startButton").isEnabled());
        assertTrue(field(panel, "statusLabel", JLabel.class).getText()
            .contains("Unable to apply OpenAPI base URL"));
    }

    @Test
    void importsOpenApiFromHttpUrlWithoutBlockingTheSwingThread() throws Exception {
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(1, 1, List.of(
            candidate("https://api.example.test/users", "/users")
        ));
        when(engine.collectPreviewFromOpenApi(anyString(), eq("openapi.json"), anyString(),
            anyString(), any(CoverageSweepOptions.class), eq(false))).thenReturn(preview);
        AtomicBoolean fetchedOnEventThread = new AtomicBoolean(true);
        AtomicReference<String> fetchedUrl = new AtomicReference<>();
        CountDownLatch fetchStarted = new CountDownLatch(1);
        AtomicReference<HttpMode> fetchedMode = new AtomicReference<>();
        OpenApiUrlFetcher fetcher = (url, httpMode) -> {
            fetchedOnEventThread.set(SwingUtilities.isEventDispatchThread());
            fetchedUrl.set(url);
            fetchedMode.set(httpMode);
            fetchStarted.countDown();
            return "{\"openapi\":\"3.0.0\",\"paths\":{}}";
        };
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine, fetcher);
        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(2);
        String malformedUrl = "https://iquery.finance.yahoo.com/ws/user-analytics/\\docs/handcrafted/swagger/openapi.json";

        assertTrue(panel.importTargetsFromUrl(malformedUrl, HttpMode.HTTP_2));
        assertTrue(fetchStarted.await(2, TimeUnit.SECONDS));
        assertFalse(fetchedOnEventThread.get());
        assertEquals(malformedUrl, fetchedUrl.get());
        assertEquals(HttpMode.HTTP_2, fetchedMode.get());
        waitForRemoteImport(panel);

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(1, table.getRowCount());
        assertEquals("/users", table.getValueAt(0, 3));
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("OpenAPI operation"));
        verify(engine).collectPreviewFromOpenApi(anyString(), eq("openapi.json"), anyString(),
            eq(malformedUrl), any(CoverageSweepOptions.class), eq(false));
    }

    @Test
    void rejectsNonHttpOpenApiUrlBeforeStartingImport() throws Exception {
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        AtomicBoolean fetched = new AtomicBoolean(false);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine, (url, httpMode) -> {
            fetched.set(true);
            return "";
        });

        assertFalse(panel.importTargetsFromUrl("file:///tmp/openapi.json"));

        assertFalse(fetched.get());
        assertTrue(field(panel, "statusLabel", JLabel.class).getText().contains("HTTP or HTTPS"));
    }

    @Test
    void importModeCheckboxTogglesStateChangingRequestSelectionWithoutHidingRows() throws Exception {
        Path spec = tempDir.resolve("openapi.yaml");
        Files.writeString(spec, "openapi: 3.0.0\npaths: {}\n");
        CoverageSweepEngine engine = mock(CoverageSweepEngine.class);
        CoverageSweepPreview preview = new CoverageSweepPreview(3, 3, List.of(
            candidate("https://api.example.test/users", "/users", "GET"),
            candidate("https://api.example.test/users", "/users", "POST"),
            candidate("https://api.example.test/users/1", "/users/1", "DELETE")
        ));
        when(engine.collectPreviewFromOpenApi(anyString(), anyString(), anyString(), eq(""),
            any(CoverageSweepOptions.class), eq(false)))
            .thenReturn(preview);
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()), engine);
        field(panel, "modeComboBox", JComboBox.class).setSelectedIndex(2);
        JCheckBox includeStateChanging = checkbox(panel, "includeUnsafeMethodsCheckBox");

        assertTrue(includeStateChanging.isEnabled());
        assertFalse(includeStateChanging.isSelected());
        assertTrue(panel.importTargetsFromFile(spec));

        JTable table = field(panel, "candidateTable", JTable.class);
        assertEquals(3, table.getRowCount());
        assertMethodSelected(table, "GET", true);
        assertMethodSelected(table, "POST", false);
        assertMethodSelected(table, "DELETE", false);

        includeStateChanging.doClick();
        assertEquals(3, table.getRowCount());
        assertMethodSelected(table, "GET", true);
        assertMethodSelected(table, "POST", true);
        assertMethodSelected(table, "DELETE", true);

        includeStateChanging.doClick();
        assertEquals(3, table.getRowCount());
        assertMethodSelected(table, "GET", true);
        assertMethodSelected(table, "POST", false);
        assertMethodSelected(table, "DELETE", false);
    }

    @Test
    void importTargetsButtonDisablesWhileSweepRuns() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403)), 250));
        button(panel, "loadButton").doClick();

        button(panel, "startButton").doClick();

        assertFalse(button(panel, "importButton").isEnabled());

        button(panel, "stopButton").doClick();
    }

    @Test
    void previewProbesButtonEnablesAfterLoadingCandidates() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403))));

        assertFalse(button(panel, "previewProbesButton").isEnabled());
        assertFalse(button(panel, "viewCandidateButton").isEnabled());

        button(panel, "loadButton").doClick();

        assertTrue(button(panel, "previewProbesButton").isEnabled());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());
    }

    @Test
    void probePreviewRendersExactGeneratedRequests() {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        HttpRequest request = request("/admin/users", "", "GET", null, "");
        HttpResponse response = response(403, "text/plain", "blocked");
        CoverageSweepCandidate candidate = new CoverageSweepCandidate(
            request,
            response,
            "key",
            request.url(),
            request.method(),
            "example.com",
            request.path(),
            403,
            response.body().length(),
            "text/plain",
            ZonedDateTime.now()
        );
        List<CoverageSweepProbe> probes = new CoverageSweepProbeGenerator().buildProbes(candidate.request(), CoverageSweepOptions.defaults());

        String preview = panel.renderProbePreview(candidate, probes);

        assertTrue(preview.contains("Probe count: 182"));
        assertTrue(preview.contains("Matrix / Extension - Path suffix ;.json"));
        assertTrue(preview.contains("GET /admin/users;.json HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/users?format=json HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/users?_format=json HTTP/1.1"));
        assertTrue(preview.contains("GET //admin/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin///users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/;/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/%3b/users HTTP/1.1"));
        assertTrue(preview.contains("GET /ADMIN/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/USERS HTTP/1.1"));
        assertTrue(preview.contains("GET /AdMiN/uSeRs HTTP/1.1"));
        assertTrue(preview.contains("GET /%61dmin/users HTTP/1.1"));
        assertTrue(preview.contains("Encoding - Double URL encode path character 1"));
        assertTrue(preview.contains("GET /%2561dmin/users HTTP/1.1"));
        assertTrue(preview.contains("GET /admin/users?debug=true HTTP/1.1"));
        assertTrue(preview.contains("Content-Type - Content-Type application/json"));
        assertTrue(preview.contains("Content-Type: application/json"));
    }

    @Test
    void startAndStopButtonsReflectRunningState() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(
            history("/blocked", 403),
            history("/another-blocked", 403)
        ), 250));
        button(panel, "loadButton").doClick();

        button(panel, "startButton").doClick();

        assertFalse(button(panel, "loadButton").isEnabled());
        assertFalse(button(panel, "startButton").isEnabled());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());
        assertFalse(button(panel, "previewProbesButton").isEnabled());
        assertTrue(button(panel, "stopButton").isEnabled());
        assertFalse(field(panel, "throttleControl", ThrottleSettingsControl.class).button().isEnabled());
        assertFalse(field(panel, "payloadSetComboBox", JComboBox.class).isEnabled());
        JTable candidateTable = field(panel, "candidateTable", JTable.class);
        assertTrue(candidateTable.isEnabled());
        assertFalse(candidateTable.isCellEditable(0, 0));
        candidateTable.setRowSelectionInterval(1, 1);
        assertEquals(1, candidateTable.getSelectedRow());
        assertTrue(button(panel, "viewCandidateButton").isEnabled());

        button(panel, "stopButton").doClick();
    }

    @Test
    void sweepResultsAppearInWorkspace() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of(history("/blocked", 403)), 0));
        button(panel, "loadButton").doClick();

        assertFalse(button(panel, "exportButton").isEnabled());

        button(panel, "startButton").doClick();

        SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
        for (int i = 0; i < 50 && (workspace.allResultsCount() == 0 || !button(panel, "exportButton").isEnabled()); i++) {
            Thread.sleep(20);
        }

        assertTrue(workspace.allResultsCount() > 0);
        assertTrue(button(panel, "exportButton").isEnabled());
    }

    @Test
    void exportsVisibleSweepResultsToTsv() throws Exception {
        CoverageSweepPanel panel = new CoverageSweepPanel(api(List.of()));
        SessionResultsWorkspace workspace = field(panel, "resultsWorkspace", SessionResultsWorkspace.class);
        HttpRequest request = request("/admin", "", "GET", null, "");
        HttpResponse response = response(200, "application/json", "{\"ok\":true}");
        workspace.addResult(new AttackResult(
            "Coverage Sweep",
            "payload\twith\nunsafe whitespace",
            "GET /admin",
            "Matrix / Extension",
            "403 -> 200",
            request,
            response
        ));

        Path output = tempDir.resolve("sweep-results.tsv");

        assertTrue(panel.exportResultsToTsv(output));

        String tsv = Files.readString(output);
        assertTrue(tsv.startsWith("#\tTarget\tFamily\tSignal\tPayload\tStatus\tLength\tContent-Type"));
        assertTrue(tsv.contains("GET /admin\tMatrix / Extension\t403 -> 200\tpayload with unsafe whitespace\t200"));
        assertFalse(tsv.contains("payload\twith"));
    }

    private MontoyaApi api(List<ProxyHttpRequestResponse> history) {
        return api(history, 0);
    }

    private MontoyaApi api(List<ProxyHttpRequestResponse> history, long responseDelayMs) {
        MontoyaApi api = mock(MontoyaApi.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        when(api.userInterface().createHttpRequestEditor()).thenAnswer(invocation -> {
            HttpRequestEditor editor = mock(HttpRequestEditor.class);
            when(editor.uiComponent()).thenReturn(new JPanel());
            return editor;
        });
        when(api.userInterface().createHttpResponseEditor()).thenAnswer(invocation -> {
            HttpResponseEditor editor = mock(HttpResponseEditor.class);
            when(editor.uiComponent()).thenReturn(new JPanel());
            return editor;
        });
        when(api.scope().isInScope(any())).thenReturn(true);
        when(api.proxy().history()).thenReturn(history);
        when(api.proxy().history(any())).thenAnswer(invocation -> {
            ProxyHistoryFilter filter = invocation.getArgument(0);
            return history.stream().filter(filter::matches).toList();
        });

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        HttpResponse response = response(403, "text/plain", "blocked");
        when(requestResponse.response()).thenReturn(response);
        when(api.http().sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            if (responseDelayMs > 0) {
                Thread.sleep(responseDelayMs);
            }
            return requestResponse;
        });
        return api;
    }

    private ProxyHttpRequestResponse history(String path, int status) {
        HttpRequest request = request(path, "", "GET", null, "");
        return history(request, status);
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status) {
        return history(request, status, "text/plain");
    }

    private ProxyHttpRequestResponse history(HttpRequest request, int status, String contentType) {
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpResponse response = response(status, contentType, "blocked");
        when(item.request()).thenReturn(request);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(item.time()).thenReturn(ZonedDateTime.now());
        return item;
    }

    private CoverageSweepCandidate candidate(String displayUrl, String path) {
        return candidate(displayUrl, path, "GET");
    }

    private CoverageSweepCandidate candidate(String displayUrl, String path, String method) {
        HttpRequest request = request(path, "", method, null, "");
        HttpResponse response = response(0, "", "");
        return new CoverageSweepCandidate(
            request,
            null,
            displayUrl,
            displayUrl,
            method,
            "victim.example",
            path,
            0,
            0,
            "",
            ZonedDateTime.now()
        );
    }

    private CoverageSweepCandidate candidate(HttpRequest request, int status) {
        return new CoverageSweepCandidate(
            request,
            response(status, "text/plain", "blocked"),
            request.method() + request.url(),
            request.url(),
            request.method(),
            "example.com",
            request.path(),
            status,
            7,
            "text/plain",
            ZonedDateTime.now()
        );
    }

    private void assertMethodSelected(JTable table, String method, boolean expected) {
        for (int row = 0; row < table.getRowCount(); row++) {
            if (method.equals(table.getValueAt(row, 1))) {
                assertEquals(expected, table.getValueAt(row, 0));
                return;
            }
        }
        throw new AssertionError("No imported row found for method " + method);
    }

    private HttpResponse response(int status, String contentType, String body) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray bodyBytes = mock(ByteArray.class);
        when(bodyBytes.length()).thenReturn(body == null ? 0 : body.length());
        when(response.statusCode()).thenReturn((short) status);
        when(response.body()).thenReturn(bodyBytes);
        when(response.headers()).thenReturn(List.of(header("Content-Type", contentType)));
        return response;
    }

    private HttpHeader header(String name, String value) {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                default -> null;
            }
        );
    }

    private JButton button(CoverageSweepPanel panel, String fieldName) throws Exception {
        return field(panel, fieldName, JButton.class);
    }

    private Component firstVisibleComponent(Container container) {
        for (Component component : container.getComponents()) {
            if (component.isVisible()) return component;
        }
        return null;
    }

    private JCheckBox checkbox(CoverageSweepPanel panel, String fieldName) throws Exception {
        return field(panel, fieldName, JCheckBox.class);
    }

    private CoverageSweepOptions currentOptions(CoverageSweepPanel panel) throws Exception {
        Method method = CoverageSweepPanel.class.getDeclaredMethod("currentOptions");
        method.setAccessible(true);
        return (CoverageSweepOptions) method.invoke(panel);
    }

    private void waitForRemoteImport(CoverageSweepPanel panel) throws Exception {
        for (int i = 0; i < 100
            && field(panel, "remoteImportWorker", javax.swing.SwingWorker.class) != null; i++) {
            Thread.sleep(20);
            SwingUtilities.invokeAndWait(() -> { });
        }
        assertTrue(field(panel, "remoteImportWorker", javax.swing.SwingWorker.class) == null);
    }

    private <T> T field(Object target, String fieldName, Class<T> type) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return type.cast(field.get(target));
    }

    private <T> T fieldUnchecked(Object target, String fieldName, Class<T> type) {
        try {
            return field(target, fieldName, type);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
