// FathomIl2cppApply.java -- apply an Il2CppDumper script.json map
// (exported by the fathom il2cpp tools as TSV) to the open Ghidra
// program, headless (Stage A).
//
// Script arguments:
//   1: output directory (result.json is written there)
//   2: methods TSV path: rva_hex <TAB> name <TAB> signature
//   3: strings TSV path: rva_hex <TAB> value
//
// Names arrive pre-sanitized by the Rust side (single source of the
// sanitization rule). Application is idempotent: a second run over
// the same map reports already_named / signatures_already /
// strings_already instead of writing again. The first name seen
// for one address wins the function name; later names at the same
// address become labels so they stay findable. Signatures are
// recorded as the function's plate comment.
//
// Bounds: row caps mirror the Rust parser caps; every counter is
// reported in result.json, including every skip class.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
//@category Rea

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class FathomIl2cppApply extends GhidraScript {

    private static final int METHODS_MAX = 1000000;
    private static final int STRINGS_MAX = 200000;
    private static final String STRING_COMMENT_PREFIX = "il2cpp-string: ";

    private long aliasedLabels = 0;
    private long alreadyNamed = 0;
    private long createdFunctions = 0;
    private long labelOnly = 0;
    private long methodsTotal = 0;
    private long midFunctionLabels = 0;
    private long nameRejected = 0;
    private long outOfRange = 0;
    private long renamed = 0;
    private long signaturesAlready = 0;
    private long signaturesApplied = 0;
    private long stringsAlready = 0;
    private long stringsApplied = 0;
    private long stringsOutOfRange = 0;
    private long stringsTotal = 0;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("FathomIl2cppApply: expected <outDir> <methodsTsv> <stringsTsv>");
            return;
        }
        long started = System.currentTimeMillis();
        File outDir = new File(args[0]);
        if (!outDir.exists() && !outDir.mkdirs()) {
            printerr("FathomIl2cppApply: cannot create out dir " + args[0]);
            return;
        }
        int tx = currentProgram.startTransaction("FathomIl2cppApply");
        boolean commit = false;
        try {
            applyMethods(new File(args[1]));
            applyStrings(new File(args[2]));
            commit = true;
        } finally {
            currentProgram.endTransaction(tx, commit);
        }
        long elapsed = System.currentTimeMillis() - started;
        StringBuilder json = new StringBuilder();
        json.append('{');
        field(json, "program", currentProgram.getName(), true);
        field(json, "image_base", currentProgram.getImageBase().toString(), false);
        num(json, "methods_total", methodsTotal);
        num(json, "renamed", renamed);
        num(json, "created_functions", createdFunctions);
        num(json, "already_named", alreadyNamed);
        num(json, "aliased_labels", aliasedLabels);
        num(json, "mid_function_labels", midFunctionLabels);
        num(json, "label_only", labelOnly);
        num(json, "name_rejected", nameRejected);
        num(json, "out_of_range", outOfRange);
        num(json, "signatures_applied", signaturesApplied);
        num(json, "signatures_already", signaturesAlready);
        num(json, "strings_total", stringsTotal);
        num(json, "strings_applied", stringsApplied);
        num(json, "strings_already", stringsAlready);
        num(json, "strings_out_of_range", stringsOutOfRange);
        num(json, "elapsed_ms", elapsed);
        json.append('}');
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(new File(outDir, "result.json"), StandardCharsets.UTF_8))) {
            writer.write(json.toString());
        }
    }

    private void applyMethods(File tsv) throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        Address base = currentProgram.getImageBase();
        Map<Long, String> firstNameByAddr = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(
                new FileReader(tsv, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (methodsTotal >= METHODS_MAX) {
                    break;
                }
                String[] parts = line.split("\t", -1);
                if (parts.length < 2) {
                    continue;
                }
                methodsTotal++;
                long rva;
                try {
                    rva = Long.parseLong(parts[0], 16);
                } catch (NumberFormatException e) {
                    outOfRange++;
                    continue;
                }
                String name = parts[1];
                String signature = parts.length >= 3 ? parts[2] : "";
                Address addr;
                try {
                    addr = base.add(rva);
                } catch (Exception e) {
                    outOfRange++;
                    continue;
                }
                String first = firstNameByAddr.putIfAbsent(rva, name);
                if (first != null && !first.equals(name)) {
                    // Shared code address: the first name owns the
                    // function; this one stays findable as a label.
                    try {
                        st.createLabel(addr, name, SourceType.USER_DEFINED);
                        aliasedLabels++;
                    } catch (Exception e) {
                        nameRejected++;
                    }
                    continue;
                }
                Function fn = fm.getFunctionAt(addr);
                if (fn == null) {
                    Function containing = fm.getFunctionContaining(addr);
                    if (containing != null) {
                        try {
                            st.createLabel(addr, name, SourceType.USER_DEFINED);
                            midFunctionLabels++;
                        } catch (Exception e) {
                            nameRejected++;
                        }
                        continue;
                    }
                    fn = createFunction(addr, name);
                    if (fn != null) {
                        createdFunctions++;
                    } else {
                        try {
                            st.createLabel(addr, name, SourceType.USER_DEFINED);
                            labelOnly++;
                        } catch (Exception e) {
                            nameRejected++;
                        }
                        continue;
                    }
                }
                if (fn.getName().equals(name)) {
                    alreadyNamed++;
                } else if (first == null) {
                    try {
                        fn.setName(name, SourceType.USER_DEFINED);
                        renamed++;
                    } catch (Exception e) {
                        try {
                            st.createLabel(addr, name, SourceType.USER_DEFINED);
                            aliasedLabels++;
                        } catch (Exception e2) {
                            nameRejected++;
                        }
                    }
                }
                if (!signature.isEmpty()) {
                    String existing = fn.getComment();
                    if (signature.equals(existing)) {
                        signaturesAlready++;
                    } else {
                        fn.setComment(signature);
                        signaturesApplied++;
                    }
                }
            }
        }
    }

    private void applyStrings(File tsv) throws Exception {
        Listing listing = currentProgram.getListing();
        Address base = currentProgram.getImageBase();
        try (BufferedReader reader = new BufferedReader(
                new FileReader(tsv, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (stringsTotal >= STRINGS_MAX) {
                    break;
                }
                String[] parts = line.split("\t", -1);
                if (parts.length < 2) {
                    continue;
                }
                stringsTotal++;
                long rva;
                try {
                    rva = Long.parseLong(parts[0], 16);
                } catch (NumberFormatException e) {
                    stringsOutOfRange++;
                    continue;
                }
                Address addr;
                try {
                    addr = base.add(rva);
                } catch (Exception e) {
                    stringsOutOfRange++;
                    continue;
                }
                String desired = STRING_COMMENT_PREFIX + parts[1];
                String existing = listing.getComment(CodeUnit.EOL_COMMENT, addr);
                if (desired.equals(existing)) {
                    stringsAlready++;
                } else {
                    listing.setComment(addr, CodeUnit.EOL_COMMENT, desired);
                    stringsApplied++;
                }
            }
        }
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
