package com.bypassfuzzer.core.scan;

import java.util.*;

/** Immutable selection shared by family shortcuts, counts, previews and execution. */
public record PlaybookSelection(BypassPlaybooks.Inventory inventory, Set<String> ids) {
    public PlaybookSelection {
        ids = ids == null ? BypassPlaybooks.resolve(inventory, null, PlaybookOptions.defaults()) : Set.copyOf(ids);
        BypassPlaybooks.resolve(inventory, null, new PlaybookOptions(ids, List.of(), true, false));
    }
    public String group(BypassPlaybooks.Descriptor d) { return inventory == BypassPlaybooks.Inventory.BYPASS ? d.family().id() : d.highSignalFamily(); }
    public Set<String> groups() {
        var groups = new LinkedHashSet<String>();
        BypassPlaybooks.available(inventory).stream().filter(d -> ids.contains(d.id())).forEach(d -> groups.add(group(d)));
        return Set.copyOf(groups);
    }
    public PlaybookSelection withFamily(String family, boolean selected) {
        var values = new LinkedHashSet<>(ids);
        BypassPlaybooks.available(inventory).stream().filter(d -> group(d).equals(family)).forEach(d -> { if (selected) values.add(d.id()); else values.remove(d.id()); });
        return new PlaybookSelection(inventory, values);
    }
    public PlaybookSelection withPlaybook(String id, boolean selected) {
        var values = new LinkedHashSet<>(ids); if (selected) values.add(id); else values.remove(id);
        return new PlaybookSelection(inventory, values);
    }
}
