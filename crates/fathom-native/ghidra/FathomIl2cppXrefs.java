// FathomIl2cppXrefs.java -- reference census for one or more
// targets in an IL2CPP-named Ghidra program, headless (Stage A).
//
// Script arguments:
//   1: output directory (result.json is written there)
//   2..n: target queries, each "rva:<hex rva>" or "name:<name>"
//
// For each target: every reference to its address, split into
// code references (the referencing address lies inside a function)
// grouped by containing function, and data references (counted
// only). Caller groups are sorted by entry address; each group
// keeps a bounded sample of referencing sites with ref types.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
//@category Rea

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class FathomIl2cppXrefs extends GhidraScript {

    private static final int CALLER_GROUPS_MAX = 8192;
    private static final int SAMPLES_PER_CALLER = 6;

    private static class Caller {
        long count = 0;
        Function function;
        List<String> samples = new ArrayList<>();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("FathomIl2cppXrefs: expected <outDir> <query> [query...]");
            return;
        }
        File outDir = new File(args[0]);
        if (!outDir.exists() && !outDir.mkdirs()) {
            printerr("FathomIl2cppXrefs: cannot create out dir " + args[0]);
            return;
        }
        StringBuilder json = new StringBuilder();
        json.append('{');
        field(json, "program", currentProgram.getName(), true);
        field(json, "image_base", currentProgram.getImageBase().toString(), false);
        json.append(",\"targets\":[");
        for (int i = 1; i < args.length; i++) {
            if (i > 1) {
                json.append(',');
            }
            appendTarget(json, args[i]);
        }
        json.append("]}");
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(new File(outDir, "result.json"), StandardCharsets.UTF_8))) {
            writer.write(json.toString());
        }
    }

    private void appendTarget(StringBuilder json, String query) {
        Address base = currentProgram.getImageBase();
        FunctionManager fm = currentProgram.getFunctionManager();
        Address addr = null;
        String resolved = null;
        if (query.startsWith("rva:")) {
            long rva = Long.parseLong(query.substring(4), 16);
            addr = base.add(rva);
        } else if (query.startsWith("name:")) {
            String name = query.substring(5);
            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator it = st.getSymbolIterator(name, true);
            while (it.hasNext()) {
                Symbol symbol = it.next();
                Function at = fm.getFunctionAt(symbol.getAddress());
                if (at != null && at.getName().equals(name)) {
                    addr = symbol.getAddress();
                    resolved = name;
                    break;
                }
                if (addr == null) {
                    addr = symbol.getAddress();
                    resolved = name;
                }
            }
        }
        json.append('{');
        field(json, "query", query, true);
        if (addr == null) {
            json.append(",\"found\":false}");
            return;
        }
        if (resolved == null) {
            Function at = fm.getFunctionAt(addr);
            resolved = at != null ? at.getName() : null;
        }
        json.append(",\"found\":true");
        field(json, "address", addr.toString(), false);
        num(json, "rva", addr.getOffset() - base.getOffset());
        if (resolved != null) {
            field(json, "resolved_name", resolved, false);
        }
        ReferenceManager rm = currentProgram.getReferenceManager();
        ReferenceIterator refs = rm.getReferencesTo(addr);
        Map<Long, Caller> byEntry = new LinkedHashMap<>();
        long codeRefs = 0;
        long dataRefs = 0;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Address from = ref.getFromAddress();
            Function containing = fm.getFunctionContaining(from);
            if (containing == null) {
                dataRefs++;
                continue;
            }
            codeRefs++;
            long entry = containing.getEntryPoint().getOffset();
            Caller caller = byEntry.computeIfAbsent(entry, key -> {
                Caller c = new Caller();
                c.function = containing;
                return c;
            });
            caller.count++;
            if (caller.samples.size() < SAMPLES_PER_CALLER) {
                caller.samples.add(from.toString() + " " + ref.getReferenceType().getName());
            }
        }
        num(json, "code_refs_total", codeRefs);
        num(json, "data_refs_total", dataRefs);
        List<Caller> callers = new ArrayList<>(byEntry.values());
        callers.sort(Comparator.comparing(c -> c.function.getEntryPoint()));
        json.append(",\"callers\":[");
        int shown = 0;
        for (Caller caller : callers) {
            if (shown >= CALLER_GROUPS_MAX) {
                break;
            }
            if (shown > 0) {
                json.append(',');
            }
            json.append('{');
            field(json, "name", caller.function.getName(), true);
            field(json, "address", caller.function.getEntryPoint().toString(), false);
            num(json, "rva", caller.function.getEntryPoint().getOffset() - base.getOffset());
            num(json, "refs", caller.count);
            json.append(",\"samples\":[");
            for (int s = 0; s < caller.samples.size(); s++) {
                if (s > 0) {
                    json.append(',');
                }
                json.append('"').append(esc(caller.samples.get(s))).append('"');
            }
            json.append("]}");
            shown++;
        }
        json.append("],\"callers_total\":").append(callers.size());
        json.append(",\"callers_truncated\":").append(callers.size() > CALLER_GROUPS_MAX);
        json.append('}');
    }

    private static void field(StringBuilder json, String key, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append('"').append(key).append("\":\"").append(esc(value)).append('"');
    }

    private static void num(StringBuilder json, String key, long value) {
        json.append(",\"").append(key).append("\":").append(value);
    }

    private static String esc(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
