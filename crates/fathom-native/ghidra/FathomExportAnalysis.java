// FathomExportAnalysis.java -- headless export for fathom (SPEC 9.1).
//
// Run by analyzeHeadless as a -postScript. Writes ONE JSON document,
// export.json, into the directory named by script argument 1.
// Script argument 2 is the mode: "overview" (default) or "function";
// in function mode, argument 3 names the function (name or address).
//
// The caps mirror crates/fathom-core/src/limits.rs (FUNCTION_COUNT_MAX,
// STRING_COUNT_MAX, SYMBOL_COUNT_MAX, INSTRUCTION_COUNT_MAX,
// DECOMPILE_BYTES_MAX): the export stays bounded no matter how large
// the analyzed binary is. Follows the estate pattern established by
// diver's DiverExportAnalysis.java; requires no network and writes
// nowhere outside the export directory.
//
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
//
//@category Rea

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class FathomExportAnalysis extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_S = 30;
    private static final long DECOMPILE_BYTES_MAX = 1024L * 1024L;
    private static final int FUNCTION_MAX = 5000;
    private static final int INSTRUCTION_MAX = 2000;
    private static final int STRING_CHARS_MAX = 200;
    private static final int STRING_MAX = 5000;
    private static final int SYMBOL_MAX = 20000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("FathomExportAnalysis: export directory argument missing");
            return;
        }
        File outDir = new File(args[0]);
        if (!outDir.exists() && !outDir.mkdirs()) {
            printerr("FathomExportAnalysis: cannot create export dir " + args[0]);
            return;
        }
        String mode = args.length >= 2 ? args[1] : "overview";
        StringBuilder json = new StringBuilder();
        json.append('{');
        appendProgram(json);
        if ("function".equals(mode) && args.length >= 3) {
            appendFunction(json, args[2]);
        } else {
            appendOverview(json);
        }
        json.append('}');
        try (BufferedWriter writer =
                new BufferedWriter(new FileWriter(new File(outDir, "export.json")))) {
            writer.write(json.toString());
        }
    }

    private void appendProgram(StringBuilder json) {
        json.append("\"program\":{");
        field(json, "name", currentProgram.getName(), true);
        field(json, "language_id",
            currentProgram.getLanguageID().toString(), false);
        field(json, "compiler_spec",
            currentProgram.getCompilerSpec().getCompilerSpecID().toString(), false);
        field(json, "address_size",
            Integer.toString(currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getSize()), false);
        field(json, "image_base",
            currentProgram.getImageBase().toString(), false);
        field(json, "executable_format",
            currentProgram.getExecutableFormat(), false);
        json.append('}');
    }

    private void appendOverview(StringBuilder json) {
        json.append(",\"memory_blocks\":[");
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (int i = 0; i < blocks.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            MemoryBlock block = blocks[i];
            json.append('{');
            field(json, "name", block.getName(), true);
            field(json, "start", block.getStart().toString(), false);
            field(json, "end", block.getEnd().toString(), false);
            json.append(",\"size\":").append(block.getSize());
            json.append(",\"read\":").append(block.isRead());
            json.append(",\"write\":").append(block.isWrite());
            json.append(",\"execute\":").append(block.isExecute());
            json.append(",\"initialized\":").append(block.isInitialized());
            json.append('}');
        }
        json.append(']');

        int functionTotal = currentProgram.getFunctionManager().getFunctionCount();
        List<String> functionRows = new ArrayList<>();
        FunctionIterator functions =
            currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && functionRows.size() < FUNCTION_MAX) {
            if (monitor.isCancelled()) {
                break;
            }
            functionRows.add(functionJson(functions.next()));
        }
        json.append(",\"functions\":[").append(String.join(",", functionRows)).append(']');
        json.append(",\"functions_total\":").append(functionTotal);
        json.append(",\"functions_truncated\":").append(functionTotal > functionRows.size());

        int stringTotal = 0;
        List<String> stringRows = new ArrayList<>();
        DataIterator dataItems = currentProgram.getListing().getDefinedData(true);
        while (dataItems.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Data data = dataItems.next();
            Object value = data.getValue();
            if (value instanceof String) {
                stringTotal++;
                if (stringRows.size() < STRING_MAX) {
                    String text = (String) value;
                    if (text.length() > STRING_CHARS_MAX) {
                        text = text.substring(0, STRING_CHARS_MAX);
                    }
                    stringRows.add("{\"address\":" + quoted(data.getAddress().toString())
                        + ",\"value\":" + quoted(text) + '}');
                }
            }
        }
        json.append(",\"strings\":[").append(String.join(",", stringRows)).append(']');
        json.append(",\"strings_total\":").append(stringTotal);
        json.append(",\"strings_truncated\":").append(stringTotal > stringRows.size());

        int symbolTotal = 0;
        List<String> symbolRows = new ArrayList<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Symbol symbol = symbols.next();
            symbolTotal++;
            if (symbolRows.size() < SYMBOL_MAX) {
                symbolRows.add("{\"address\":" + quoted(symbol.getAddress().toString())
                    + ",\"name\":" + quoted(symbol.getName())
                    + ",\"type\":" + quoted(symbol.getSymbolType().toString())
                    + ",\"source\":" + quoted(symbol.getSource().toString()) + '}');
            }
        }
        json.append(",\"symbols\":[").append(String.join(",", symbolRows)).append(']');
        json.append(",\"symbols_total\":").append(symbolTotal);
        json.append(",\"symbols_truncated\":").append(symbolTotal > symbolRows.size());
    }

    private void appendFunction(StringBuilder json, String target) {
        Function fn = findFunction(target);
        json.append(",\"mode\":\"function\"");
        if (fn == null) {
            json.append(",\"function_found\":false");
            json.append(",\"function_target\":").append(quoted(target));
            return;
        }
        json.append(",\"function_found\":true");
        json.append(",\"function\":").append(functionJson(fn));

        List<String> rows = new ArrayList<>();
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(fn.getBody(), true);
        while (instructions.hasNext() && rows.size() < INSTRUCTION_MAX) {
            if (monitor.isCancelled()) {
                break;
            }
            Instruction instruction = instructions.next();
            rows.add("{\"address\":" + quoted(instruction.getAddress().toString())
                + ",\"text\":" + quoted(instruction.toString()) + '}');
        }
        json.append(",\"listing\":[").append(String.join(",", rows)).append(']');
        json.append(",\"listing_truncated\":").append(rows.size() >= INSTRUCTION_MAX);

        List<String> callers = new ArrayList<>();
        for (Function caller : fn.getCallingFunctions(monitor)) {
            callers.add(quoted(caller.getName() + '@' + caller.getEntryPoint()));
        }
        json.append(",\"callers\":[").append(String.join(",", callers)).append(']');
        List<String> callees = new ArrayList<>();
        for (Function callee : fn.getCalledFunctions(monitor)) {
            callees.add(quoted(callee.getName() + '@' + callee.getEntryPoint()));
        }
        json.append(",\"callees\":[").append(String.join(",", callees)).append(']');

        List<String> refs = new ArrayList<>();
        ReferenceIterator references =
            currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        while (references.hasNext() && refs.size() < INSTRUCTION_MAX) {
            Reference reference = references.next();
            RefType type = reference.getReferenceType();
            refs.add("{\"from\":" + quoted(reference.getFromAddress().toString())
                + ",\"type\":" + quoted(type.toString()) + '}');
        }
        json.append(",\"references_to\":[").append(String.join(",", refs)).append(']');

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        if (decompiler.openProgram(currentProgram)) {
            try {
                DecompileResults results =
                    decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_S, monitor);
                if (results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null) {
                    String c = results.getDecompiledFunction().getC();
                    boolean truncated = c.length() > DECOMPILE_BYTES_MAX;
                    if (truncated) {
                        c = c.substring(0, (int) DECOMPILE_BYTES_MAX);
                    }
                    json.append(",\"decompile\":{\"bytes\":").append(c.length());
                    json.append(",\"truncated\":").append(truncated);
                    json.append(",\"c\":").append(quoted(c)).append('}');
                }
            } finally {
                decompiler.dispose();
            }
        }
    }

    private Function findFunction(String target) {
        FunctionIterator functions =
            currentProgram.getFunctionManager().getFunctions(true);
        Function byAddress = null;
        while (functions.hasNext()) {
            Function fn = functions.next();
            if (fn.getName().equals(target)) {
                return fn;
            }
            if (fn.getEntryPoint().toString().equals(target)) {
                byAddress = fn;
            }
        }
        return byAddress;
    }

    private String functionJson(Function fn) {
        StringBuilder row = new StringBuilder();
        row.append('{');
        field(row, "address", fn.getEntryPoint().toString(), true);
        field(row, "name", fn.getName(), false);
        field(row, "signature", fn.getSignature().toString(), false);
        row.append(",\"body_size\":").append(fn.getBody().getNumAddresses());
        row.append(",\"classification\":").append(quoted(classification(fn)));
        row.append(",\"calling_convention\":")
            .append(quoted(String.valueOf(fn.getCallingConventionName())));
        row.append('}');
        return row.toString();
    }

    private static String classification(Function fn) {
        if (fn.isThunk()) {
            return "thunk";
        }
        if (fn.isExternal()) {
            return "external";
        }
        return "defined";
    }

    private static void field(StringBuilder json, String name, String value, boolean first) {
        if (!first) {
            json.append(',');
        }
        json.append(quoted(name)).append(':').append(quoted(value));
    }

    // Minimal JSON string escaping: quotes, backslash, and control
    // characters. Everything else passes through as UTF-16 text,
    // which the JSON writer emits as UTF-8.
    private static String quoted(String text) {
        if (text == null) {
            return "\"\"";
        }
        StringBuilder out = new StringBuilder(text.length() + 2);
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
        return out.toString();
    }
}
