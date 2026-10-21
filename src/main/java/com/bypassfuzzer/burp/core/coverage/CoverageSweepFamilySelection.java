package com.bypassfuzzer.burp.core.coverage;

import com.bypassfuzzer.burp.core.attacks.AttackType;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Enabled payload families for each of Sweep's two payload inventories. */
public record CoverageSweepFamilySelection(
    Set<String> highSignalFamilies,
    Set<AttackType> bypassFamilies
) {

    public static final List<String> HIGH_SIGNAL_FAMILIES = com.bypassfuzzer.core.scan.HighSignalPlanner.ORDERED_FAMILIES;

    public CoverageSweepFamilySelection {
        highSignalFamilies = highSignalFamilies == null
            ? Set.copyOf(HIGH_SIGNAL_FAMILIES)
            : Set.copyOf(new LinkedHashSet<>(highSignalFamilies));
        bypassFamilies = bypassFamilies == null
            ? Set.copyOf(EnumSet.allOf(AttackType.class))
            : Set.copyOf(bypassFamilies);
    }

    public static CoverageSweepFamilySelection defaults() {
        return new CoverageSweepFamilySelection(null, null);
    }

    public boolean highSignalEnabled(String family) {
        return "Control".equals(family) || highSignalFamilies.contains(family);
    }

    public boolean bypassEnabled(AttackType family) {
        return bypassFamilies.contains(family);
    }
}
