package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.coverage.*;
import com.bypassfuzzer.burp.http.RequestSender;
import org.junit.jupiter.api.Test;
import javax.swing.*;
import java.util.*;
import static com.bypassfuzzer.burp.testsupport.HttpRequestTestFactory.requestWithHeaders;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CapturedApiSpecImportTest {
    private static final String SPEC="""
        {"openapi":"3.0.1","info":{"title":"Owned API","version":"v1"},"paths":{
          "/api/healthCheck":{"get":{"responses":{"200":{"description":"Success"}}}},
          "/Saml/RequestImage":{"post":{"responses":{"200":{"description":"Success"}}}},
          "/Saml/InitiateSingleLogout":{"get":{"responses":{"200":{"description":"Success"}}}}}}
        """;
    private static Object field(Object object,String name) throws Exception {
        var f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);
    }
    private CoverageSweepPanel panel(CoverageSweepEngine engine) throws Exception {
        var ctor=CoverageSweepPanelTest.class.getDeclaredConstructor();ctor.setAccessible(true);var fixture=ctor.newInstance();
        var apiMethod=CoverageSweepPanelTest.class.getDeclaredMethod("api",List.class);apiMethod.setAccessible(true);
        var api=(MontoyaApi)apiMethod.invoke(fixture,List.of());
        return new CoverageSweepPanel(api,engine==null ? SweepEngineTestFactory.importedEngine(api,mock(RequestSender.class)) : engine,
            (url,mode) -> {throw new AssertionError("Captured spec must never be fetched again");});
    }
    private HttpRequestResponse captured(String source) {
        var request=requestWithHeaders("/Swagger/v1/\\swagger.json","","GET",Map.of("Referer","https://example.com/allowed","X-Original-URL","/Swagger/v1/swagger.json","Authorization","Bearer fixture-only","Content-Length","0"),"");
        var response=mock(HttpResponse.class);var bytes=mock(ByteArray.class);when(bytes.length()).thenReturn(source.length());
        when(response.body()).thenReturn(bytes);when(response.bodyToString()).thenReturn(source);
        var exchange=mock(HttpRequestResponse.class);when(exchange.request()).thenReturn(request);when(exchange.response()).thenReturn(response);return exchange;
    }
    private void finished(CoverageSweepPanel panel) throws Exception {
        long end=System.nanoTime()+5_000_000_000L;
        while(field(panel,"remoteImportWorker")!=null && System.nanoTime()<end){Thread.sleep(20);SwingUtilities.invokeAndWait(() -> {});}
        assertNull(field(panel,"remoteImportWorker"));
    }
    @Test void importsThreeOperationsFromCapturedBypassWithoutRefetchOrScan() throws Exception {
        var panel=panel(null);
        try {
            SwingUtilities.invokeAndWait(() -> assertTrue(panel.importApiSpecResponse(captured(SPEC))));finished(panel);
            var table=(JTable)field(panel,"candidateTable");assertEquals(3,table.getRowCount());
            var model=field(panel,"candidateTableModel");var selected=model.getClass().getDeclaredMethod("selectedCandidates");selected.setAccessible(true);
            @SuppressWarnings("unchecked") var candidates=(List<CoverageSweepCandidate>)selected.invoke(model);
            assertEquals(2,candidates.size(),"POST stays visible but unchecked by default");
            for(var c:candidates){assertEquals("https://example.com/allowed",c.request().headerValue("Referer"));assertEquals("Bearer fixture-only",c.request().headerValue("Authorization"));assertEquals("/Swagger/v1/swagger.json",c.request().headerValue("X-Original-URL"));assertFalse(c.displayUrl().contains("Swagger"));}
            assertTrue(((JLabel)field(panel,"statusLabel")).getText().contains("Imported 3"));
            assertTrue(((JButton)field(panel,"startButton")).isEnabled());assertFalse(((JButton)field(panel,"stopButton")).isEnabled());
            panel.setOpenApiVariables(Map.of());assertEquals(3,table.getRowCount());
        }finally{panel.cleanup();}
    }
    @Test void declaredOtherOriginDoesNotInheritCapturedCredentials() throws Exception {
        var panel=panel(null);
        try {
            var source=SPEC.replace("\"paths\":","\"servers\":[{\"url\":\"https://other.example\"}],\"paths\":");
            SwingUtilities.invokeAndWait(() -> assertTrue(panel.importApiSpecResponse(captured(source))));finished(panel);
            var model=field(panel,"candidateTableModel");var selected=model.getClass().getDeclaredMethod("selectedCandidates");selected.setAccessible(true);
            for(Object row:(List<?>)selected.invoke(model)) {var c=(CoverageSweepCandidate)row;assertFalse(c.request().hasHeader("Authorization"));assertFalse(c.request().hasHeader("Referer"));}
        }finally{panel.cleanup();}
    }
    @Test void runningSweepRejectsCapturedImportWithoutReplacingCandidates() throws Exception {
        var engine=mock(CoverageSweepEngine.class);when(engine.isRunning()).thenReturn(true);var panel=panel(engine);
        try{SwingUtilities.invokeAndWait(() -> assertFalse(panel.importApiSpecResponse(captured(SPEC))));assertNull(field(panel,"remoteImportWorker"));verify(engine,never()).collectPreviewFromOpenApi(anyString(),anyString(),anyString(),anyString(),any(),anyBoolean(),any());}
        finally{panel.cleanup();}
    }
    @Test void invalidCapturedBodyDoesNotStartAScanOrFallBackToFetching() throws Exception {
        var panel=panel(null);
        try {
            SwingUtilities.invokeAndWait(() -> assertTrue(panel.importApiSpecResponse(captured("<html>not an API spec</html>"))));finished(panel);
            assertEquals(0,((JTable)field(panel,"candidateTable")).getRowCount());assertFalse(((JButton)field(panel,"startButton")).isEnabled());
            assertTrue(((JLabel)field(panel,"statusLabel")).getText().contains("Unable to import"));
        }finally{panel.cleanup();}
    }
    @Test void candidateViewerLeavesHeaderlessNativeEditorTablesUntouched() throws Exception {
        var panel=panel(null);
        try {
            var api=(MontoyaApi)field(panel,"api");var nativeTable=new JTable();nativeTable.setTableHeader(null);var background=java.awt.Color.MAGENTA;nativeTable.setBackground(background);
            var editor=mock(burp.api.montoya.ui.editor.HttpRequestEditor.class);when(editor.uiComponent()).thenReturn(nativeTable);when(api.userInterface().createHttpRequestEditor()).thenReturn(editor);
            var candidate=new CoverageSweepCandidate(requestWithHeaders("/api/healthCheck","","GET",Map.of(),""),null,"one","https://example.com/api/healthCheck","GET","example.com","/api/healthCheck",0,0,"",null);
            var method=CoverageSweepPanel.class.getDeclaredMethod("candidateExchange",CoverageSweepCandidate.class);method.setAccessible(true);
            var view=(JSplitPane)method.invoke(panel,candidate);
            assertDoesNotThrow(() -> com.bypassfuzzer.burp.ui.WorkbenchTheme.apply(view));assertEquals(background,nativeTable.getBackground());assertNull(nativeTable.getTableHeader());
        }finally{panel.cleanup();}
    }
}
