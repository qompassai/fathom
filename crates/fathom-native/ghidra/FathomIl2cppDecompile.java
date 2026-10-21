// FathomIl2cppDecompile.java -- decompile one function from an
// IL2CPP-named Ghidra program, headless (Stage A).
//
// Script arguments:
//   1: output directory (result.json is written there)
//   2: query: "rva:<hex rva>" or "name:<il2cpp name>"
//
// Output: the target function (name/address/RVA as applied by the
// map), its decompiled C (byte-capped, truncation reported), and
// its depth-1 callees named via the applied map. Callee order is
// by entry address: deterministic across runs.
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
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class FathomIl2cppDecompile extends GhidraScript {

    private static final int CALLEES_MAX = 1024;
    private static final long DECOMPILE_BYTES_MAX = 1024L * 1024L;
    private static final int DECOMPILE_TIMEOUT_S = 60;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("FathomIl2cppDecompile: expected <outDir> <query>");
            return;
        }
        File outDir = new File(args[0]);
        if (!outDir.exists() && !outDir.mkdirs()) {
            printerr("FathomIl2cppDecompile: cannot create out dir " + args[0]);
            return;
        }
        String query = args[1];
        String matchKind = "none";
        Function target = null;
        if (query.startsWith("rva:")) {
            long rva = Long.parseLong(query.substring(4), 16);
            Address addr = currentProgram.getImageBase().add(rva);
            FunctionManager fm = currentProgram.getFunctionManager();
            target = fm.getFunctionAt(addr);
            if (target == null) {
                target = fm.getFunctionContaining(addr);
            }
            if (target != null) {
                matchKind = "rva";
            }
        } else if (query.startsWith("name:")) {
            target = resolveByName(query.substring(5));
            if (target != null) {
                matchKind = "name";
            }
        }
        StringBuilder json = new StringBuilder();
        json.append('{');
        field(json, "program", currentProgram.getName(), true);
        field(json, "image_base", currentProgram.getImageBase().toString(), false);
        field(json, "query", query, false);
        field(json, "match", matchKind, false);
        json.append(",\"found\":").append(target != null);
        if (target != null) {
            appendFunction(json, target);
            appendDecompile(json, target);
            appendCallees(json, target);
        }
        json.append('}');
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(new File(outDir, "result.json"), StandardCharsets.UTF_8))) {
            writer.write(json.toString());
        }
    }

    private Function resolveByName(String name) {
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolIterator it = st.getSymbolIterator(name, true);
        Function containing = null;
        while (it.hasNext()) {
            Symbol symbol = it.next();
            Function at = fm.getFunctionAt(symbol.getAddress());
            if (at != null && at.getName().equals(name)) {
                return at;
            }
            if (containing == null) {
                Function inside = fm.getFunctionContaining(symbol.getAddress());
                if (inside != null) {
                    containing = inside;
                }
            }
        }
        return containing;
    }

    private void appendFunction(StringBuilder json, Function fn) {
        json.append(",\"function\":{");
        field(json, "name", fn.getName(), true);
        field(json, "address", fn.getEntryPoint().toString(), false);
        num(json, "rva", fn.getEntryPoint().getOffset()
            - currentProgram.getImageBase().getOffset());
        num(json, "body_size", fn.getBody().getNumAddresses());
        field(json, "signature", fn.getSignature().toString(), false);
        String comment = fn.getComment();
        if (comment != null && !comment.isEmpty()) {
            field(json, "map_signature", comment, false);
        }
        json.append('}');
    }

    private void appendDecompile(StringBuilder json, Function fn) {
        DecompInterface dec = new DecompInterface();
        dec.toggleCCode(true);
        dec.toggleSyntaxTree(false);
        dec.setSimplificationStyle("decompile");
        String c = null;
        String error = null;
        try {
            if (!dec.openProgram(currentProgram)) {
                error = "decompiler could not open the program";
            } else {
                DecompileResults res = dec.decompileFunction(fn, DECOMPILE_TIMEOUT_S, monitor);
                if (res != null && res.getDecompiledFunction() != null) {
                    c = res.getDecompiledFunction().getC();
                } else if (res != null) {
                    error = res.getErrorMessage();
                } else {
                    error = "decompiler returned no result";
                }
            }
        } finally {
            dec.dispose();
        }
        json.append(",\"decompile\":{");
        if (c == null) {
            json.append("\"c\":null");
            field(json, "error", error == null ? "unknown" : error, false);
            num(json, "bytes", 0);
            json.append(",\"truncated\":false");
        } else {
            boolean truncated = c.length() > DECOMPILE_BYTES_MAX;
            String kept = truncated ? c.substring(0, (int) DECOMPILE_BYTES_MAX) : c;
            field(json, "c", kept, true);
            num(json, "bytes", c.length());
            json.append(",\"truncated\":").append(truncated);
        }
        json.append('}');
    }

    private void appendCallees(StringBuilder json, Function fn) {
        Set<Function> called = fn.getCalledFunctions(monitor);
        List<Function> sorted = new ArrayList<>(called);
        sorted.sort(Comparator.comparing(Function::getEntryPoint));
        json.append(",\"callees\":[");
        long base = currentProgram.getImageBase().getOffset();
        int shown = 0;
        for (Function callee : sorted) {
            if (shown >= CALLEES_MAX) {
                break;
            }
            if (shown > 0) {
                json.append(',');
            }
            json.append('{');
            field(json, "name", callee.getName(), true);
            field(json, "address", callee.getEntryPoint().toString(), false);
            num(json, "rva", callee.getEntryPoint().getOffset() - base);
            json.append('}');
            shown++;
        }
        json.append("],\"callees_total\":").append(sorted.size());
        json.append(",\"callees_truncated\":").append(sorted.size() > CALLEES_MAX);
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
