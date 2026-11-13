package com.bypassfuzzer.burp.ui.session;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.attacks.AttackResult;
import com.bypassfuzzer.burp.core.coverage.CoverageSweepClassifier;
import com.bypassfuzzer.burp.http.*;
import com.bypassfuzzer.core.scan.*;
import java.util.*;
import java.util.function.*;

/** Matching controls for a manual retry's current header and credential context. */
final class LiveRetryContext {
    private record Control(HttpRequest request,HttpResponse response) { }
    private final Map<String,Control> controls=new HashMap<>();
    private final LiveRun run;
    private final Set<String> authHeaders,authCookies;
    private final Set<Integer> throttleCodes;
    private final Consumer<AttackResult> evidence;
    LiveRetryContext(LiveRun run,Set<String> authHeaders,Set<String> authCookies,Set<Integer> throttleCodes,Consumer<AttackResult> evidence) {
        this.run=run;this.authHeaders=authHeaders;this.authCookies=authCookies;this.throttleCodes=throttleCodes;this.evidence=evidence;
    }
    private Control control(String seed,String label,ControlRole role,HttpRequest request,Function<HttpRequest,HttpResponse> send,long revision) {
        String key=run.snapshot().headerRevision()+"\n"+seed+"\n"+role;
        var old=controls.get(key);if(old!=null)return old;
        var response=send.apply(request);var value=new Control(request,response);controls.put(key,value);
        evidence.accept(new AttackResult("Retry control",label,seed,"Control","Control",request,response)
            .withEvidenceMetadata(new AttackResult.EvidenceMetadata("",role,WildcardCalibration.Assessment.DISABLED,null,null).withRun(null,revision)));
        return value;
    }
    AttackResult prepare(AttackResult previous,long revision,Function<HttpRequest,HttpResponse> send) {
        var config=run.snapshot().configuration();var access=MontoyaRequestAccess.INSTANCE;var policy=config.policy(access);
        var metadata=previous.getEvidenceMetadata();boolean anonymous=metadata.sweepContext()!=null && metadata.sweepContext().authenticated();
        var workflow=new SweepWorkflow<HttpRequest,HttpResponse>(access,CoverageSweepClassifier::toCore);
        HttpRequest oldBase=previous.getOriginalRequest()==null ? previous.getRequest() : previous.getOriginalRequest();
        HttpRequest baseline=policy.reconcileMutation(oldBase,config.prepare(oldBase,access));
        String seed=previous.getTargetLabel()+"\n"+new CoreRequestAdapter().fromMontoya(previous.getRequest()).protocol();
        var original=control(seed,"Original control for edited retry",ControlRole.ORIGINAL,baseline,send,revision);
        Control verification=null;
        if(previous.getVerificationRequest()!=null) {
            HttpRequest verify=config.prepare(previous.getVerificationRequest(),access);
            if(anonymous)verify=workflow.stripAuthentication(verify,authHeaders,authCookies);
            var verificationPolicy=anonymous ? policy.withoutAuthentication(authHeaders,authCookies) : policy;
            verify=verificationPolicy.reconcileMutation(verify,verify);
            verification=control(seed,"Comparison control for edited retry",ControlRole.TARGET,verify,send,revision);
        }
        var mutationPolicy=anonymous ? policy.withoutAuthentication(authHeaders,authCookies) : policy;
        HttpRequest mutation=previous.getRequest();for(String name:config.removeHeaders())mutation=access.removeHeader(mutation,name);
        if(anonymous)mutation=workflow.stripAuthentication(mutation,authHeaders,authCookies);
        mutation=mutationPolicy.reconcileMutation(oldBase,mutation);
        Control fallback=null;
        if(metadata.fallbackRequest()!=null && WildcardCalibration.eligible(mutation.method())) {
            HttpRequest siblingSeed=anonymous && verification!=null ? verification.request() : original.request();
            HttpRequest sibling=WildcardCalibration.control(siblingSeed,access);
            fallback=control(seed,"Wildcard sibling control for edited retry",ControlRole.WILDCARD,sibling,send,revision);
        }
        SweepClassifier.Context context=metadata.sweepContext();
        if(context!=null) {
            var response=CoverageSweepClassifier.toCore(original.response());
            var baselineSummary=response==null ? new SweepClassifier.Baseline(0,0,"") : new SweepClassifier.Baseline(response.statusCode(),response.contentLength(),response.contentType());
            context=new SweepClassifier.Context(anonymous,baselineSummary,response,verification==null ? null : CoverageSweepClassifier.toCore(verification.response()),throttleCodes);
        }
        var refreshed=new AttackResult.EvidenceMetadata(metadata.playbookId(),metadata.controlRole(),metadata.calibration(),fallback==null ? null : fallback.request(),fallback==null ? null : fallback.response(),context,metadata.comparison(),revision);
        return new AttackResult(previous.getAttackType(),previous.getPayload(),previous.getTargetLabel(),previous.getPayloadFamily(),previous.getPayloadEncoding(),mutation,null,original.request(),original.response(),
            verification==null ? null : verification.request(),verification==null ? null : verification.response()).withEvidenceMetadata(refreshed);
    }
}
