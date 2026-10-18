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
// SPDX-License-Identifier: Apache-2.0
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
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
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
    private static final int FUNCTION_MAX = 50000;
    private static final int INSTRUCTION_MAX = 2000;
    private static final int STRING_CHARS_MAX = 200;
    // Byte-run values get a larger cap: Go/Rust string blobs are
    // long concatenated runs, and a 200-char cap silently cut
    // content (and search hits) deep inside a run.
    private static final int DATA_STRING_CHARS_MAX = 4096;
    private static final int STRING_MAX = 50000;
    private static final int SYMBOL_MAX = 20000;
    // Export harvest bound: the row caps above are generous so
    // search_inventory can see past the provider's returned-row
    // limits (fathom-core STRING_COUNT_MAX/FUNCTION_COUNT_MAX);
    // this per-array byte budget is what actually binds, keeping
    // the whole export under the engine's OUTPUT_BYTES_MAX.
    private static final long EXPORT_BYTES_MAX = 1500L * 1024L;
    // Byte-run string harvest (finds literals Ghidra does not define,
    // notably unterminated Rust/Go strings): printable-ASCII runs of
    // at least DATA_STRING_MIN bytes in initialized memory, with an
    // aggregate scan budget so a huge image cannot make the export
    // unbounded.
    private static final int DATA_STRING_MAX = 50000;
    private static final int DATA_STRING_MIN = 4;
    private static final long DATA_SCAN_BYTES_MAX = 64L * 1024L * 1024L;
    private static final int DATA_SCAN_CHUNK_BYTES = 1024 * 1024;

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
        long functionBytes = 0;
        FunctionIterator functions =
            currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && functionRows.size() < FUNCTION_MAX
                && functionBytes < EXPORT_BYTES_MAX) {
            if (monitor.isCancelled()) {
                break;
            }
            String row = functionJson(functions.next());
            functionRows.add(row);
            functionBytes += row.length();
        }
        json.append(",\"functions\":[").append(String.join(",", functionRows)).append(']');
        json.append(",\"functions_total\":").append(functionTotal);
        json.append(",\"functions_truncated\":").append(functionTotal > functionRows.size());

        int stringTotal = 0;
        List<String> stringRows = new ArrayList<>();
        long stringBytes = 0;
        DataIterator dataItems = currentProgram.getListing().getDefinedData(true);
        while (dataItems.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Data data = dataItems.next();
            Object value = data.getValue();
            if (value instanceof String) {
                stringTotal++;
                if (stringRows.size() < STRING_MAX && stringBytes < EXPORT_BYTES_MAX) {
                    String text = (String) value;
                    if (text.length() > STRING_CHARS_MAX) {
                        text = text.substring(0, STRING_CHARS_MAX);
                    }
                    String row = "{\"address\":" + quoted(data.getAddress().toString())
                        + ",\"value\":" + quoted(text) + '}';
                    stringRows.add(row);
                    stringBytes += row.length();
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

        appendDataStrings(json);
    }

    // Harvest printable-ASCII byte runs from initialized memory.
    // Ghidra only *defines* strings it can delimit (a terminator or
    // a recognized length prefix), which misses the dominant string
    // form of Rust and Go binaries: unterminated literals sitting in
    // .rodata. The export reports these separately as data_strings
    // so the provider can present them as derived evidence, never
    // silently merged with the defined set.
    private void appendDataStrings(StringBuilder json) {
        List<String> rows = new ArrayList<>();
        long dataBytes = 0;
        long total = 0;
        long scanned = 0;
        boolean capped = false;
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            if (monitor.isCancelled() || capped) {
                break;
            }
            if (!block.isInitialized() || !block.isRead()) {
                continue;
            }
            long remaining = block.getSize();
            Address cursor = block.getStart();
            while (remaining > 0) {
                if (monitor.isCancelled() || scanned >= DATA_SCAN_BYTES_MAX) {
                    capped = scanned >= DATA_SCAN_BYTES_MAX;
                    break;
                }
                int want = (int) Math.min((long) DATA_SCAN_CHUNK_BYTES, remaining);
                byte[] buffer = new byte[want];
                int got;
                try {
                    got = block.getBytes(cursor, buffer);
                } catch (Exception e) {
                    break; // unreadable range: stop this block, keep others
                }
                if (got <= 0) {
                    break;
                }
                scanned += got;
                long runStart = -1;
                StringBuilder runText = new StringBuilder();
                for (int i = 0; i < got; i++) {
                    int b = buffer[i] & 0xff;
                    if (b >= 0x20 && b <= 0x7e) {
                        if (runStart < 0) {
                            runStart = i;
                            runText.setLength(0);
                        }
                        if (runText.length() < DATA_STRING_CHARS_MAX) {
                            runText.append((char) b);
                        }
                    } else {
                        if (runStart >= 0 && i - runStart >= DATA_STRING_MIN) {
                            total++;
                            if (rows.size() < DATA_STRING_MAX && dataBytes < EXPORT_BYTES_MAX) {
                                String row = "{\"address\":"
                                    + quoted(cursor.add(runStart).toString())
                                    + ",\"value\":" + quoted(runText.toString()) + '}';
                                rows.add(row);
                                dataBytes += row.length();
                            }
                        }
                        runStart = -1;
                    }
                }
                if (runStart >= 0 && got - runStart >= DATA_STRING_MIN) {
                    total++;
                    if (rows.size() < DATA_STRING_MAX && dataBytes < EXPORT_BYTES_MAX) {
                        String row = "{\"address\":"
                            + quoted(cursor.add(runStart).toString())
                            + ",\"value\":" + quoted(runText.toString()) + '}';
                        rows.add(row);
                        dataBytes += row.length();
                    }
                }
                cursor = cursor.add(got);
                remaining -= got;
            }
        }
        json.append(",\"data_strings\":[").append(String.join(",", rows)).append(']');
        json.append(",\"data_strings_total\":").append(total);
        json.append(",\"data_strings_truncated\":").append(total > rows.size());
        json.append(",\"data_strings_scan_capped\":").append(capped);
    }

    private void appendFunction(StringBuilder json, String target) {
        FunctionMatch match = findFunction(target);
        Function fn = match.function;
        json.append(",\"mode\":\"function\"");
        json.append(",\"function_match\":").append(quoted(match.via));
        if (!match.candidates.isEmpty()) {
            json.append(",\"function_candidates\":[");
            for (int i = 0; i < match.candidates.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                json.append(quoted(match.candidates.get(i)));
            }
            json.append(']');
        }
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

    // The outcome of one function lookup: the function (or null),
    // how it matched, and — when the query was ambiguous — the
    // candidate names so the provider can report them instead of
    // silently picking one.
    private static final class FunctionMatch {
        final List<String> candidates = new ArrayList<>();
        Function function;
        String via = "none";
    }

    // Resolution ladder (first rung that decides wins):
    //   1. exact Ghidra name;
    //   2. qualified name ending in "::target" or ".target"
    //      (Go's main.foo, C++ namespaces, DWARF-qualified names);
    //   3. demangled simple name (Rust v0/legacy mangling, C++);
    //   4. case-insensitive name or qualified name (defensive:
    //      some importers normalize case differently from the
    //      source, and callers routinely query a differently-cased
    //      form of the recorded name);
    //   5. entry-point address.
    // Rungs 2-4 must match exactly one function; more than one is
    // reported as ambiguous candidates, never a guess.
    private FunctionMatch findFunction(String target) {
        FunctionMatch match = new FunctionMatch();
        FunctionIterator functions =
            currentProgram.getFunctionManager().getFunctions(true);
        List<Function> all = new ArrayList<>();
        while (functions.hasNext()) {
            all.add(functions.next());
        }
        for (Function fn : all) {
            if (fn.getName().equals(target)) {
                match.function = fn;
                match.via = "exact";
                return match;
            }
        }
        List<Function> qualified = new ArrayList<>();
        for (Function fn : all) {
            String name = fn.getName();
            if (name.endsWith("::" + target) || name.endsWith("." + target)) {
                qualified.add(fn);
            }
        }
        if (qualified.size() == 1) {
            match.function = qualified.get(0);
            match.via = "qualified";
            return match;
        }
        if (qualified.size() > 1) {
            for (Function fn : qualified) {
                match.candidates.add(fn.getName());
            }
            return match;
        }
        List<Function> demangled = new ArrayList<>();
        for (Function fn : all) {
            try {
                DemangledObject object =
                    DemanglerUtil.demangle(currentProgram, fn.getName());
                if (object != null && target.equals(object.getName())) {
                    demangled.add(fn);
                }
            } catch (Exception e) {
                // An undemangleable symbol is skipped, never fatal.
            }
        }
        if (demangled.size() == 1) {
            match.function = demangled.get(0);
            match.via = "demangled";
            return match;
        }
        if (demangled.size() > 1) {
            for (Function fn : demangled) {
                match.candidates.add(fn.getName());
            }
            return match;
        }
        String targetFolded = target.toLowerCase(java.util.Locale.ROOT);
        List<Function> casefold = new ArrayList<>();
        for (Function fn : all) {
            String folded = fn.getName().toLowerCase(java.util.Locale.ROOT);
            if (folded.equals(targetFolded)
                || folded.endsWith("::" + targetFolded)
                || folded.endsWith("." + targetFolded)) {
                casefold.add(fn);
            }
        }
        if (casefold.size() == 1) {
            match.function = casefold.get(0);
            match.via = "casefold";
            return match;
        }
        if (casefold.size() > 1) {
            for (Function fn : casefold) {
                match.candidates.add(fn.getName());
            }
            return match;
        }
        for (Function fn : all) {
            if (fn.getEntryPoint().toString().equals(target)) {
                match.function = fn;
                match.via = "address";
                return match;
            }
        }
        return match;
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
