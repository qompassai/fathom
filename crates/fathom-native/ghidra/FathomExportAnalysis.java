// FathomExportAnalysis.java -- headless export for fathom (SPEC 9.1).
//
// Run by analyzeHeadless as a -postScript. Writes ONE JSON document,
// export.json, into the directory named by script argument 1.
// Script argument 2 is the mode: "overview" (default) or "function";
// in function mode, argument 3 names the function (name or address).
//
// The read-core modes (addresses, bytes, callgraph, decompile,
// detail, disasm, insns, program, types) take their query, when they
// have one, as argument 3 in lowercase hex of its UTF-8 bytes: a
// query can then never begin with '-' and be read by analyzeHeadless
// as one of its own options. Every array these modes emit is a
// bounded section {"rows":[...],"total":N,"truncated":bool}.
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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.PropertyMapManager;

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

    // Read-core caps (mirrored where the provider validates inputs:
    // fathom-core limits.rs ADDRESS_QUERY_COUNT_MAX,
    // BYTE_PATTERN_BYTES_MAX, BYTE_PATTERN_COUNT_MAX,
    // DECOMPILE_BATCH_COUNT_MAX, DISASSEMBLE_BYTES_MAX). Row caps
    // bound the count; the per-section byte budgets keep one
    // multi-section export under the engine's OUTPUT_BYTES_MAX
    // (8 MiB): the budgets of any one mode sum to at most 6 MiB.
    private static final int ADDRESS_BYTES_WINDOW = 64;
    private static final int ADDRESS_CONTEXT_INSTRUCTIONS = 16;
    private static final int ADDRESS_QUERY_MAX = 32;
    private static final int BYTE_PATTERN_MAX = 32;
    private static final int CALLEE_MAX = 256;
    private static final int COMPONENT_MAX = 512;
    private static final int DECOMPILE_BATCH_BYTES_MAX = 256 * 1024;
    private static final int DECOMPILE_BATCH_MAX = 8;
    private static final int DISASSEMBLE_BYTES_MAX = 4096;
    private static final int INSTRUCTION_SCAN_MAX = 2000000;
    private static final int MATCH_MAX = 1000;
    private static final int ROW_MAX = 50000;
    private static final long SECTION_BYTES_LARGE = 1024L * 1024L;
    private static final long SECTION_BYTES_MEDIUM = 512L * 1024L;
    private static final long SECTION_BYTES_SMALL = 128L * 1024L;
    private static final long SECTION_BYTES_TINY = 64L * 1024L;
    private static final long VALUE_CHARS_MAX = 200;

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
        String query = args.length >= 3 ? args[2] : null;
        if ("function".equals(mode) && query != null) {
            appendFunction(json, query);
        } else if (READ_CORE_MODES.contains(mode)) {
            json.append(",\"mode\":").append(quoted(mode));
            String decoded = query == null ? "" : decodeHex(query);
            if (decoded == null) {
                json.append(",\"query_error\":\"query argument is not lowercase hex\"");
            } else {
                appendReadCore(json, mode, decoded);
            }
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

    // ---------------------------------------------------------------
    // Read core (fathom Ghidra G1). Each mode writes one top-level
    // section; every array inside it is a bounded Rows section.
    // ---------------------------------------------------------------

    private static final java.util.Set<String> READ_CORE_MODES = new java.util.TreeSet<>(
        java.util.Arrays.asList("addresses", "bytes", "callgraph", "decompile", "detail",
            "disasm", "insns", "program", "types"));

    private static final CommentType[] COMMENT_TYPES = {
        CommentType.EOL, CommentType.PLATE, CommentType.POST, CommentType.PRE,
        CommentType.REPEATABLE,
    };
    // Code-gap padding rule: alignment fill decodes as these
    // mnemonics; a gap holding only them is not an undefined function.
    private static final java.util.Set<String> PADDING_MNEMONICS = new java.util.TreeSet<>(
        java.util.Arrays.asList("INT3", "NOP"));
    private static final int GAP_SCAN_INSTRUCTIONS = 4096;
    private static final int COMMENT_CHARS_MAX = 2000;
    private static final int COMMENT_COUNT_SCAN_MAX = 1000;
    private static final int PCODE_OP_MAX = 20000;

    private void appendReadCore(StringBuilder json, String mode, String query) throws Exception {
        switch (mode) {
            case "addresses":
                appendAddresses(json, query);
                break;
            case "bytes":
                appendByteSearch(json, query);
                break;
            case "callgraph":
                appendCallGraph(json);
                break;
            case "decompile":
                appendDecompiles(json, query);
                break;
            case "detail":
                appendDetail(json, query);
                break;
            case "disasm":
                appendDisassembly(json, query);
                break;
            case "insns":
                appendInstructionSearch(json, query);
                break;
            case "program":
                appendProgramFacts(json);
                break;
            case "types":
                appendTypes(json);
                break;
            default:
                break;
        }
    }

    // A bounded array: rows retained up to a count cap and a byte
    // budget; every offered row is counted, so total > rows.size()
    // is the truncation signal, never silence.
    private static final class Rows {
        private final long bytesMax;
        private long bytes = 0;
        private final int countMax;
        private final List<String> rows = new ArrayList<>();
        private long total = 0;

        Rows(int countMax, long bytesMax) {
            this.countMax = countMax;
            this.bytesMax = bytesMax;
        }

        // Whether another row would be retained. Callers skip the
        // costly part of building a row once this is false.
        boolean open() {
            return rows.size() < countMax && bytes < bytesMax;
        }

        void add(String row) {
            total++;
            if (open()) {
                rows.add(row);
                bytes += row.length();
            }
        }

        void skip() {
            total++;
        }

        String json() {
            return "{\"rows\":[" + String.join(",", rows) + "],\"total\":" + total
                + ",\"truncated\":" + (total > rows.size()) + "}";
        }
    }

    // A JSON object builder over the script's own escaping.
    private static final class Obj {
        private boolean first = true;
        private final StringBuilder out = new StringBuilder("{");

        private Obj key(String name) {
            if (!first) {
                out.append(',');
            }
            first = false;
            out.append(quoted(name)).append(':');
            return this;
        }

        Obj bool(String name, boolean value) {
            key(name).out.append(value);
            return this;
        }

        String done() {
            return out.append('}').toString();
        }

        Obj num(String name, long value) {
            key(name).out.append(value);
            return this;
        }

        Obj raw(String name, String json) {
            key(name).out.append(json);
            return this;
        }

        Obj str(String name, String value) {
            key(name).out.append(quoted(value));
            return this;
        }
    }

    private static String addr(Address address) {
        return address == null ? "" : address.toString();
    }

    private static String array(List<String> rows) {
        return "[" + String.join(",", rows) + "]";
    }

    private static String clip(String text) {
        if (text == null) {
            return "";
        }
        return text.length() > VALUE_CHARS_MAX ? text.substring(0, (int) VALUE_CHARS_MAX) : text;
    }

    private static String commentTypeName(CommentType type) {
        return type.name().toLowerCase(Locale.ROOT);
    }

    // Lowercase hex of UTF-8 bytes -> text; null when malformed.
    private static String decodeHex(String hex) {
        if (hex.length() % 2 != 0) {
            return null;
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(String.format("%02x", b & 0xff));
        }
        return out.toString();
    }

    private static boolean isUndefined(DataType type) {
        return type == null || type.getName().startsWith("undefined");
    }

    private static String quotedArray(List<String> values) {
        List<String> rows = new ArrayList<>();
        for (String value : values) {
            rows.add(quoted(value));
        }
        return array(rows);
    }

    private Address resolveAddress(String text) {
        try {
            return currentProgram.getAddressFactory().getAddress(text);
        } catch (Exception e) {
            return null; // malformed or out of every address space
        }
    }

    private void appendComments(AddressIterator addresses, Rows rows) {
        Listing listing = currentProgram.getListing();
        while (addresses.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Address address = addresses.next();
            for (CommentType type : COMMENT_TYPES) {
                String text = listing.getComment(type, address);
                if (text == null) {
                    continue;
                }
                if (!rows.open()) {
                    rows.skip();
                    continue;
                }
                boolean cut = text.length() > COMMENT_CHARS_MAX;
                rows.add(new Obj()
                    .str("address", addr(address))
                    .str("text", cut ? text.substring(0, COMMENT_CHARS_MAX) : text)
                    .bool("text_truncated", cut)
                    .str("type", commentTypeName(type))
                    .done());
            }
        }
    }

    // ---- addresses: per-address facts for up to ADDRESS_QUERY_MAX.

    private void appendAddresses(StringBuilder json, String query) {
        String[] items = query.split("\n");
        List<String> rows = new ArrayList<>();
        for (int i = 0; i < items.length && i < ADDRESS_QUERY_MAX; i++) {
            rows.add(addressJson(items[i]));
        }
        json.append(",\"addresses\":").append(array(rows));
    }

    private String addressJson(String text) {
        Obj row = new Obj().str("query", text);
        Address address = resolveAddress(text);
        if (address == null) {
            return row.bool("valid", false).done();
        }
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        ReferenceManager refs = currentProgram.getReferenceManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        row.bool("valid", true).str("address", addr(address));
        MemoryBlock block = memory.getBlock(address);
        row.bool("in_memory", block != null).str("block", block == null ? "" : block.getName());

        Function fn = currentProgram.getFunctionManager().getFunctionContaining(address);
        row.raw("function", fn == null ? "null"
            : new Obj().str("address", addr(fn.getEntryPoint())).str("name", fn.getName()).done());

        CodeUnit unit = listing.getCodeUnitContaining(address);
        row.raw("code_unit", unit == null ? "null" : codeUnitJson(unit));
        Data data = listing.getDataContaining(address);
        row.raw("data", data == null ? "null" : dataRegionJson(data, address));

        List<String> symbolRows = new ArrayList<>();
        for (Symbol symbol : symbols.getSymbols(address)) {
            symbolRows.add(new Obj()
                .str("name", symbol.getName())
                .str("namespace", symbol.getParentNamespace() == null ? ""
                    : symbol.getParentNamespace().getName(true))
                .bool("primary", symbol.isPrimary())
                .str("source", String.valueOf(symbol.getSource()))
                .str("type", symbol.getSymbolType().toString())
                .done());
        }
        row.raw("symbols", array(symbolRows));

        List<String> commentRows = new ArrayList<>();
        for (CommentType type : COMMENT_TYPES) {
            String comment = listing.getComment(type, address);
            if (comment != null) {
                boolean cut = comment.length() > COMMENT_CHARS_MAX;
                commentRows.add(new Obj()
                    .str("text", cut ? comment.substring(0, COMMENT_CHARS_MAX) : comment)
                    .bool("text_truncated", cut)
                    .str("type", commentTypeName(type))
                    .done());
            }
        }
        row.raw("comments", array(commentRows));

        Rows refsTo = new Rows(MATCH_MAX, SECTION_BYTES_TINY);
        ReferenceIterator incoming = refs.getReferencesTo(address);
        while (incoming.hasNext()) {
            Reference ref = incoming.next();
            if (!refsTo.open()) {
                refsTo.skip();
                continue;
            }
            Function from = currentProgram.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            refsTo.add(new Obj()
                .str("from", addr(ref.getFromAddress()))
                .str("from_function", from == null ? "" : from.getName())
                .str("type", ref.getReferenceType().toString())
                .done());
        }
        row.raw("references_to", refsTo.json());

        Rows refsFrom = new Rows(MATCH_MAX, SECTION_BYTES_TINY);
        for (Reference ref : refs.getReferencesFrom(address)) {
            refsFrom.add(new Obj()
                .str("to", addr(ref.getToAddress()))
                .str("type", ref.getReferenceType().toString())
                .done());
        }
        row.raw("references_from", refsFrom.json());

        Instruction at = listing.getInstructionContaining(address);
        Address anchor = at == null ? address : at.getAddress();
        List<String> before = new ArrayList<>();
        Instruction previous = listing.getInstructionBefore(anchor);
        while (previous != null && before.size() < ADDRESS_CONTEXT_INSTRUCTIONS) {
            before.add(0, contextJson(previous));
            previous = listing.getInstructionBefore(previous.getAddress());
        }
        List<String> after = new ArrayList<>();
        Instruction next = listing.getInstructionAfter(anchor);
        while (next != null && after.size() < ADDRESS_CONTEXT_INSTRUCTIONS) {
            after.add(contextJson(next));
            next = listing.getInstructionAfter(next.getAddress());
        }
        row.raw("context_after", array(after))
            .raw("context_at", at == null ? "null" : contextJson(at))
            .raw("context_before", array(before));

        byte[] window = new byte[ADDRESS_BYTES_WINDOW];
        String bytesHex = "";
        try {
            int got = memory.getBytes(address, window);
            bytesHex = hex(java.util.Arrays.copyOf(window, Math.max(got, 0)));
        } catch (Exception e) {
            bytesHex = ""; // unreadable (uninitialized or absent)
        }
        row.str("bytes", bytesHex);
        return row.done();
    }

    private static String codeUnitJson(CodeUnit unit) {
        Obj row = new Obj()
            .str("kind", unit instanceof Instruction ? "instruction" : "data")
            .num("length", unit.getLength())
            .str("start", addr(unit.getMinAddress()))
            .str("text", clip(unit.toString()));
        if (unit instanceof Data) {
            Data data = (Data) unit;
            row.str("data_type", data.getDataType().getName())
                .bool("defined", data.isDefined())
                .str("value", clip(data.getDefaultValueRepresentation()));
        }
        return row.done();
    }

    private String contextJson(Instruction instruction) {
        return new Obj()
            .str("address", addr(instruction.getAddress()))
            .str("text", instruction.toString())
            .done();
    }

    private String dataRegionJson(Data data, Address address) {
        int offset = (int) address.subtract(data.getMinAddress());
        Data primitive = data.getPrimitiveAt(offset);
        Obj row = new Obj()
            .num("component_count", data.getNumComponents())
            .bool("defined", data.isDefined())
            .str("label", data.getLabel() == null ? "" : data.getLabel())
            .num("length", data.getLength())
            .num("offset", offset)
            .num("references_to",
                currentProgram.getReferenceManager().getReferenceCountTo(data.getMinAddress()))
            .str("start", addr(data.getMinAddress()))
            .str("type", data.getDataType().getName())
            .str("value", clip(data.getDefaultValueRepresentation()));
        if (primitive != null && primitive != data) {
            row.raw("component", new Obj()
                .str("path", primitive.getComponentPathName() == null ? ""
                    : primitive.getComponentPathName())
                .str("start", addr(primitive.getMinAddress()))
                .str("type", primitive.getDataType().getName())
                .str("value", clip(primitive.getDefaultValueRepresentation()))
                .done());
        }
        return row.done();
    }

    // ---- bytes: masked pattern search over initialized memory.

    private void appendByteSearch(StringBuilder json, String query) throws Exception {
        List<String> patterns = new ArrayList<>();
        String[] lines = query.split("\n");
        for (int i = 0; i < lines.length && i < BYTE_PATTERN_MAX; i++) {
            int tab = lines[i].indexOf('\t');
            if (tab < 0) {
                continue;
            }
            patterns.add(bytePatternJson(lines[i].substring(0, tab), lines[i].substring(tab + 1)));
        }
        json.append(",\"byte_search\":")
            .append(new Obj().raw("patterns", array(patterns)).done());
    }

    private String bytePatternJson(String label, String pattern) throws Exception {
        int count = pattern.length() / 2;
        byte[] bytes = new byte[count];
        byte[] mask = new byte[count];
        for (int i = 0; i < count; i++) {
            String pair = pattern.substring(2 * i, 2 * i + 2);
            if ("??".equals(pair)) {
                bytes[i] = 0;
                mask[i] = 0;
            } else {
                bytes[i] = (byte) Integer.parseInt(pair, 16);
                mask[i] = (byte) 0xff;
            }
        }
        Memory memory = currentProgram.getMemory();
        Rows matches = new Rows(MATCH_MAX, SECTION_BYTES_SMALL);
        boolean stopped = false;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || stopped) {
                continue;
            }
            Address cursor = block.getStart();
            while (cursor != null) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (!matches.open()) {
                    stopped = true;
                    break;
                }
                Address found = memory.findBytes(cursor, block.getEnd(), bytes, mask, true, monitor);
                if (found == null) {
                    break;
                }
                Function fn = currentProgram.getFunctionManager().getFunctionContaining(found);
                matches.add(new Obj()
                    .str("address", addr(found))
                    .str("block", block.getName())
                    .str("function", fn == null ? "" : fn.getName())
                    .done());
                cursor = found.next();
                if (cursor != null && cursor.compareTo(block.getEnd()) > 0) {
                    break;
                }
            }
        }
        return new Obj()
            .str("label", label)
            .raw("matches", matches.json())
            .str("pattern", pattern)
            .bool("stopped_at_cap", stopped)
            .done();
    }

    // ---- callgraph: call edges for every function (bounded).

    private void appendCallGraph(StringBuilder json) throws Exception {
        Rows rows = new Rows(ROW_MAX, 4L * SECTION_BYTES_LARGE);
        appendCallRows(currentProgram.getFunctionManager().getFunctions(true), rows);
        appendCallRows(currentProgram.getFunctionManager().getExternalFunctions(), rows);
        json.append(",\"callgraph\":").append(new Obj().raw("functions", rows.json()).done());
    }

    private void appendCallRows(FunctionIterator functions, Rows rows) throws Exception {
        ReferenceManager refs = currentProgram.getReferenceManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        while (functions.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Function fn = functions.next();
            if (!rows.open()) {
                rows.skip();
                continue;
            }
            List<String> callees = new ArrayList<>();
            int calleeTotal = 0;
            for (Function callee : fn.getCalledFunctions(monitor)) {
                calleeTotal++;
                if (callees.size() < CALLEE_MAX) {
                    callees.add(quoted(addr(callee.getEntryPoint())));
                }
            }
            java.util.Collections.sort(callees);
            rows.add(new Obj()
                .str("address", addr(fn.getEntryPoint()))
                .raw("callees", array(callees))
                .bool("callees_truncated", calleeTotal > callees.size())
                .str("classification", classification(fn))
                .bool("is_entry_point", symbols.isExternalEntryPoint(fn.getEntryPoint()))
                .str("name", fn.getName())
                .num("references_to", refs.getReferenceCountTo(fn.getEntryPoint()))
                .done());
        }
    }

    // ---- decompile: bounded C for up to DECOMPILE_BATCH_MAX functions.

    private void appendDecompiles(StringBuilder json, String query) throws Exception {
        String[] names = query.split("\n");
        List<String> rows = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        boolean open = decompiler.openProgram(currentProgram);
        try {
            for (int i = 0; i < names.length && i < DECOMPILE_BATCH_MAX; i++) {
                FunctionMatch match = findFunction(names[i]);
                Obj row = new Obj()
                    .raw("candidates", quotedArray(match.candidates))
                    .str("match", match.via)
                    .str("query", names[i]);
                if (match.function == null) {
                    rows.add(row.bool("found", false).done());
                    continue;
                }
                row.bool("found", true).raw("function", functionJson(match.function));
                if (!open) {
                    rows.add(row.str("error", "the decompiler did not open the program").done());
                    continue;
                }
                DecompileResults results =
                    decompiler.decompileFunction(match.function, DECOMPILE_TIMEOUT_S, monitor);
                if (results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null) {
                    String c = results.getDecompiledFunction().getC();
                    boolean truncated = c.length() > DECOMPILE_BATCH_BYTES_MAX;
                    if (truncated) {
                        c = c.substring(0, DECOMPILE_BATCH_BYTES_MAX);
                    }
                    row.num("bytes", c.length()).str("c", c).bool("truncated", truncated);
                } else {
                    row.str("error", results == null ? "no decompiler result"
                        : String.valueOf(results.getErrorMessage()));
                }
                rows.add(row.done());
            }
        } finally {
            decompiler.dispose();
        }
        json.append(",\"decompiles\":").append(array(rows));
    }

    // ---- detail: everything per-function tools query, one run.

    private void appendDetail(StringBuilder json, String target) throws Exception {
        FunctionMatch match = findFunction(target);
        Obj detail = new Obj()
            .raw("candidates", quotedArray(match.candidates))
            .str("match", match.via)
            .str("query", target);
        Function fn = match.function;
        if (fn == null) {
            json.append(",\"detail\":").append(detail.bool("found", false).done());
            return;
        }
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        detail.bool("found", true)
            .raw("doc", functionDocJson(fn))
            .raw("function", functionJson(fn))
            .str("plate_comment", fn.getComment() == null ? ""
                : fn.getComment().substring(0, Math.min(fn.getComment().length(),
                    COMMENT_CHARS_MAX)));

        Rows parameters = new Rows(ROW_MAX, SECTION_BYTES_TINY);
        for (Parameter parameter : fn.getParameters()) {
            parameters.add(variableJson(parameter, parameter.getOrdinal()));
        }
        Rows locals = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        for (Variable local : fn.getLocalVariables()) {
            locals.add(variableJson(local, -1));
        }
        detail.raw("locals", locals.json()).raw("parameters", parameters.json());

        Rows instructions = new Rows(INSTRUCTION_MAX, 3L * SECTION_BYTES_LARGE / 2L);
        long pcodeTotal = 0;
        long pcodeKept = 0;
        InstructionIterator iterator = listing.getInstructions(fn.getBody(), true);
        while (iterator.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Instruction instruction = iterator.next();
            if (!instructions.open()) {
                instructions.skip();
                continue;
            }
            List<String> flows = new ArrayList<>();
            for (Address flow : instruction.getFlows()) {
                flows.add(quoted(addr(flow)));
            }
            List<String> pcode = new ArrayList<>();
            for (PcodeOp op : instruction.getPcode()) {
                pcodeTotal++;
                if (pcodeKept < PCODE_OP_MAX) {
                    pcode.add(rawPcodeJson(op));
                    pcodeKept++;
                }
            }
            List<String> refsFrom = new ArrayList<>();
            for (Reference ref : instruction.getReferencesFrom()) {
                refsFrom.add(new Obj()
                    .str("to", addr(ref.getToAddress()))
                    .str("type", ref.getReferenceType().toString())
                    .done());
            }
            String bytes;
            try {
                bytes = hex(instruction.getBytes());
            } catch (Exception e) {
                bytes = "";
            }
            instructions.add(new Obj()
                .str("address", addr(instruction.getAddress()))
                .str("bytes", bytes)
                .str("fallthrough", addr(instruction.getFallThrough()))
                .str("flow_type", instruction.getFlowType().toString())
                .raw("flows", array(flows))
                .str("mnemonic", instruction.getMnemonicString())
                .raw("pcode", array(pcode))
                .raw("references_from", array(refsFrom))
                .str("text", instruction.toString())
                .done());
        }
        detail.raw("instructions", instructions.json())
            .num("pcode_ops_retained", pcodeKept)
            .num("pcode_ops_total", pcodeTotal);

        Rows labels = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        SymbolIterator labelIt = symbols.getSymbols(fn.getBody(), SymbolType.LABEL, true);
        while (labelIt.hasNext()) {
            Symbol symbol = labelIt.next();
            labels.add(new Obj()
                .str("address", addr(symbol.getAddress()))
                .str("name", symbol.getName())
                .bool("primary", symbol.isPrimary())
                .str("source", String.valueOf(symbol.getSource()))
                .done());
        }
        detail.raw("labels", labels.json());

        Rows blocks = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        CodeBlockIterator blockIt = model.getCodeBlocksContaining(fn.getBody(), monitor);
        while (blockIt.hasNext()) {
            CodeBlock block = blockIt.next();
            if (!blocks.open()) {
                blocks.skip();
                continue;
            }
            List<String> destinations = new ArrayList<>();
            CodeBlockReferenceIterator destIt = block.getDestinations(monitor);
            while (destIt.hasNext()) {
                CodeBlockReference ref = destIt.next();
                destinations.add(new Obj()
                    .str("flow_type", ref.getFlowType().toString())
                    .str("to", addr(ref.getDestinationAddress()))
                    .done());
            }
            blocks.add(new Obj()
                .raw("destinations", array(destinations))
                .str("end", addr(block.getMaxAddress()))
                .num("size", block.getNumAddresses())
                .str("start", addr(block.getFirstStartAddress()))
                .done());
        }
        detail.raw("blocks", blocks.json());

        Rows refsTo = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        ReferenceIterator incoming = refs.getReferencesTo(fn.getEntryPoint());
        while (incoming.hasNext()) {
            Reference ref = incoming.next();
            if (!refsTo.open()) {
                refsTo.skip();
                continue;
            }
            Function from = currentProgram.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            refsTo.add(new Obj()
                .str("from", addr(ref.getFromAddress()))
                .str("from_function", from == null ? "" : from.getName())
                .str("type", ref.getReferenceType().toString())
                .done());
        }
        detail.raw("references_to", refsTo.json());

        List<String> callers = new ArrayList<>();
        for (Function caller : fn.getCallingFunctions(monitor)) {
            callers.add(new Obj().str("address", addr(caller.getEntryPoint()))
                .str("name", caller.getName()).done());
        }
        List<String> callees = new ArrayList<>();
        for (Function callee : fn.getCalledFunctions(monitor)) {
            callees.add(new Obj().str("address", addr(callee.getEntryPoint()))
                .str("classification", classification(callee))
                .str("name", callee.getName()).done());
        }
        detail.raw("callees", array(callees)).raw("callers", array(callers));

        Rows comments = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        appendComments(listing.getCommentAddressIterator(fn.getBody(), true), comments);
        detail.raw("comments", comments.json());

        Rows strings = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        AddressIterator sources = refs.getReferenceSourceIterator(fn.getBody(), true);
        while (sources.hasNext()) {
            Address from = sources.next();
            for (Reference ref : refs.getReferencesFrom(from)) {
                Data data = listing.getDataAt(ref.getToAddress());
                if (data != null && data.getValue() instanceof String) {
                    strings.add(new Obj()
                        .str("address", addr(data.getAddress()))
                        .str("from", addr(from))
                        .str("value", clip((String) data.getValue()))
                        .done());
                }
            }
        }
        detail.raw("strings_referenced", strings.json());
        detail.raw("high", highJson(fn));
        json.append(",\"detail\":").append(detail.done());
    }

    private String highJson(Function fn) {
        Obj high = new Obj();
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                return high.bool("available", false)
                    .str("reason", "the decompiler did not open the program").done();
            }
            DecompileResults results =
                decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_S, monitor);
            HighFunction function = results == null ? null : results.getHighFunction();
            if (function == null) {
                return high.bool("available", false)
                    .str("reason", results == null ? "no decompiler result"
                        : String.valueOf(results.getErrorMessage()))
                    .done();
            }
            Rows ops = new Rows(PCODE_OP_MAX, 2L * SECTION_BYTES_LARGE);
            Iterator<PcodeOpAST> opIt = function.getPcodeOps();
            while (opIt.hasNext()) {
                PcodeOpAST op = opIt.next();
                if (!ops.open()) {
                    ops.skip();
                    continue;
                }
                ops.add(highOpJson(op));
            }
            Rows symbols = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
            Iterator<HighSymbol> symbolIt = function.getLocalSymbolMap().getSymbols();
            while (symbolIt.hasNext()) {
                HighSymbol symbol = symbolIt.next();
                symbols.add(new Obj()
                    .str("name", symbol.getName())
                    .bool("parameter", symbol.isParameter())
                    .str("storage", symbol.getStorage() == null ? ""
                        : symbol.getStorage().toString())
                    .str("type", symbol.getDataType() == null ? ""
                        : symbol.getDataType().getName())
                    .done());
            }
            return high.bool("available", true)
                .raw("ops", ops.json())
                .raw("symbols", symbols.json())
                .done();
        } finally {
            decompiler.dispose();
        }
    }

    private static String highOpJson(PcodeOpAST op) {
        List<String> inputs = new ArrayList<>();
        for (Varnode input : op.getInputs()) {
            inputs.add(varnodeJson(input));
        }
        return new Obj()
            .str("address", addr(op.getSeqnum().getTarget()))
            .raw("inputs", array(inputs))
            .str("op", op.getMnemonic())
            .raw("output", varnodeJson(op.getOutput()))
            .num("time", op.getSeqnum().getTime())
            .done();
    }

    private static String rawPcodeJson(PcodeOp op) {
        List<String> inputs = new ArrayList<>();
        for (Varnode input : op.getInputs()) {
            inputs.add(quoted(input == null ? "" : input.toString()));
        }
        return new Obj()
            .raw("inputs", array(inputs))
            .str("op", op.getMnemonic())
            .str("output", op.getOutput() == null ? "" : op.getOutput().toString())
            .done();
    }

    private static String varnodeJson(Varnode varnode) {
        if (varnode == null) {
            return "null";
        }
        HighVariable high = varnode.getHigh();
        return new Obj()
            .bool("constant", varnode.isConstant())
            .str("high", high == null || high.getName() == null ? "" : high.getName())
            .num("id", varnode instanceof VarnodeAST ? ((VarnodeAST) varnode).getUniqueId() : -1)
            .num("offset", varnode.getOffset())
            .num("size", varnode.getSize())
            .str("space", varnode.getAddress().getAddressSpace().getName())
            .str("type", high == null || high.getDataType() == null ? ""
                : high.getDataType().getName())
            .done();
    }

    private static String variableJson(Variable variable, int ordinal) {
        return new Obj()
            .num("first_use_offset", variable.getFirstUseOffset())
            .str("name", variable.getName())
            .num("ordinal", ordinal)
            .str("source", String.valueOf(variable.getSource()))
            .str("storage", variable.getVariableStorage().toString())
            .str("type", variable.getDataType().getName())
            .num("type_length", variable.getLength())
            .done();
    }

    // ---- disasm: read-only pseudo-disassembly (the listing is not
    // modified; PseudoDisassembler decodes without creating code).

    private void appendDisassembly(StringBuilder json, String query) {
        String[] parts = query.split("\n");
        Obj out = new Obj().str("query", parts[0]);
        Address start = resolveAddress(parts[0]);
        int length;
        try {
            length = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;
        } catch (NumberFormatException e) {
            length = 0;
        }
        if (start == null || length <= 0 || length > DISASSEMBLE_BYTES_MAX) {
            json.append(",\"disassembly\":").append(out.bool("valid", false).done());
            return;
        }
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        PseudoDisassembler disassembler = new PseudoDisassembler(currentProgram);
        List<String> rows = new ArrayList<>();
        Address cursor = start;
        long consumed = 0;
        String stopped = "length_reached";
        while (consumed < length) {
            if (!memory.contains(cursor)) {
                stopped = "left_memory";
                break;
            }
            PseudoInstruction instruction;
            try {
                instruction = disassembler.disassemble(cursor);
            } catch (Exception e) {
                stopped = "undecodable: " + e.getClass().getSimpleName();
                break;
            }
            if (instruction == null) {
                stopped = "undecodable";
                break;
            }
            String bytes;
            try {
                bytes = hex(instruction.getBytes());
            } catch (Exception e) {
                bytes = "";
            }
            rows.add(new Obj()
                .str("address", addr(cursor))
                .str("bytes", bytes)
                .num("length", instruction.getLength())
                .bool("listing_instruction", listing.getInstructionAt(cursor) != null)
                .str("text", instruction.toString())
                .done());
            consumed += instruction.getLength();
            try {
                cursor = cursor.addNoWrap(instruction.getLength());
            } catch (Exception e) {
                stopped = "address_overflow";
                break;
            }
        }
        json.append(",\"disassembly\":").append(out
            .num("consumed", consumed)
            .bool("in_memory", memory.contains(start))
            .raw("instructions", array(rows))
            .num("requested_length", length)
            .str("start", addr(start))
            .str("stopped", stopped)
            .bool("valid", true)
            .done());
    }

    // ---- insns: instruction search. Each query line is one term:
    // "m:<mnemonic>" (exact, case-insensitive) or "t:<text>"
    // (case-insensitive substring of the rendered instruction).

    private void appendInstructionSearch(StringBuilder json, String query) {
        List<String> terms = new ArrayList<>();
        for (String line : query.split("\n")) {
            if (line.length() > 2 && (line.startsWith("m:") || line.startsWith("t:"))) {
                terms.add(line.toLowerCase(Locale.ROOT));
            }
        }
        Listing listing = currentProgram.getListing();
        Rows matches = new Rows(MATCH_MAX, SECTION_BYTES_MEDIUM);
        long scanned = 0;
        boolean capped = false;
        InstructionIterator iterator = listing.getInstructions(true);
        while (iterator.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            if (scanned >= INSTRUCTION_SCAN_MAX) {
                capped = true;
                break;
            }
            Instruction instruction = iterator.next();
            scanned++;
            String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
            String text = instruction.toString().toLowerCase(Locale.ROOT);
            String hit = null;
            for (String term : terms) {
                String needle = term.substring(2);
                boolean matched = term.startsWith("m:") ? mnemonic.equals(needle)
                    : text.contains(needle);
                if (matched) {
                    hit = term;
                    break;
                }
            }
            if (hit == null) {
                continue;
            }
            if (!matches.open()) {
                matches.skip();
                continue;
            }
            Function fn = currentProgram.getFunctionManager()
                .getFunctionContaining(instruction.getAddress());
            matches.add(new Obj()
                .str("address", addr(instruction.getAddress()))
                .str("function", fn == null ? "" : fn.getName())
                .str("mnemonic", instruction.getMnemonicString())
                .str("term", hit)
                .str("text", instruction.toString())
                .done());
        }
        json.append(",\"instruction_search\":").append(new Obj()
            .num("instructions_total", listing.getNumInstructions())
            .raw("matches", matches.json())
            .bool("scan_capped", capped)
            .num("scanned", scanned)
            .raw("terms", quotedArray(terms))
            .done());
    }

    // ---- program: program-level facts (options, comments, tags,
    // namespaces, externals, data items, gaps, properties, project).

    private void appendProgramFacts(StringBuilder json) throws Exception {
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        ReferenceManager refs = currentProgram.getReferenceManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        Obj facts = new Obj();

        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        facts.raw("analysis", new Obj()
            .bool("analyzed", info.getBoolean(Program.ANALYZED_OPTION_NAME, false))
            .bool("analyzed_option_present", info.contains(Program.ANALYZED_OPTION_NAME))
            .done());

        Rows analyzers = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        Rows groups = new Rows(ROW_MAX, SECTION_BYTES_TINY);
        Rows options = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        for (String group : currentProgram.getOptionsNames()) {
            Options opts = currentProgram.getOptions(group);
            List<String> names = opts.getOptionNames();
            groups.add(new Obj().str("name", group).num("option_count", names.size()).done());
            for (String name : names) {
                String type = String.valueOf(opts.getType(name));
                String value;
                boolean readable = true;
                try {
                    value = clip(opts.getValueAsString(name));
                } catch (Exception e) {
                    value = "";
                    readable = false;
                }
                boolean isDefault = opts.isDefaultValue(name);
                options.add(new Obj()
                    .str("group", group)
                    .bool("is_default", isDefault)
                    .str("name", name)
                    .str("type", type)
                    .str("value", value)
                    .bool("value_readable", readable)
                    .done());
                if (Program.ANALYSIS_PROPERTIES.equals(group) && name.indexOf('.') < 0
                    && "BOOLEAN_TYPE".equals(type)) {
                    analyzers.add(new Obj()
                        .bool("enabled", opts.getBoolean(name, false))
                        .bool("is_default", isDefault)
                        .str("name", name)
                        .done());
                }
            }
        }
        facts.raw("analyzers", analyzers.json());

        Rows bookmarks = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        Iterator<Bookmark> bookmarkIt = currentProgram.getBookmarkManager().getBookmarksIterator();
        while (bookmarkIt.hasNext()) {
            Bookmark bookmark = bookmarkIt.next();
            if (!bookmarks.open()) {
                bookmarks.skip();
                continue;
            }
            bookmarks.add(new Obj()
                .str("address", addr(bookmark.getAddress()))
                .str("category", bookmark.getCategory())
                .str("comment", clip(bookmark.getComment()))
                .str("type", bookmark.getTypeString())
                .done());
        }
        facts.raw("bookmarks", bookmarks.json());

        PrototypeModel defaultModel = currentProgram.getCompilerSpec().getDefaultCallingConvention();
        List<String> conventions = new ArrayList<>();
        for (PrototypeModel model : currentProgram.getCompilerSpec().getCallingConventions()) {
            conventions.add(new Obj()
                .bool("is_default", defaultModel != null
                    && model.getName().equals(defaultModel.getName()))
                .str("name", model.getName())
                .done());
        }
        facts.raw("calling_conventions", array(conventions));

        Rows namespaces = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        Rows members = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        SymbolIterator defined = symbols.getDefinedSymbols();
        while (defined.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Symbol symbol = defined.next();
            SymbolType type = symbol.getSymbolType();
            if (type != SymbolType.NAMESPACE && type != SymbolType.CLASS
                && type != SymbolType.LIBRARY) {
                continue;
            }
            int childCount = 0;
            SymbolIterator children = symbols.getChildren(symbol);
            while (children.hasNext()) {
                Symbol child = children.next();
                childCount++;
                if (type != SymbolType.CLASS) {
                    continue;
                }
                if (!members.open()) {
                    members.skip();
                    continue;
                }
                members.add(new Obj()
                    .str("address", addr(child.getAddress()))
                    .str("class", symbol.getName(true))
                    .str("name", child.getName())
                    .str("source", String.valueOf(child.getSource()))
                    .str("type", child.getSymbolType().toString())
                    .done());
            }
            namespaces.add(new Obj()
                .str("full_name", symbol.getName(true))
                .num("member_count", childCount)
                .str("name", symbol.getName())
                .str("parent", symbol.getParentNamespace() == null ? ""
                    : symbol.getParentNamespace().getName(true))
                .str("type", type.toString())
                .done());
        }
        facts.raw("class_members", members.json());

        AddressSet gapsSet = new AddressSet();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                gapsSet.add(block.getStart(), block.getEnd());
            }
        }
        FunctionIterator bodies = currentProgram.getFunctionManager().getFunctions(true);
        while (bodies.hasNext()) {
            gapsSet.delete(bodies.next().getBody());
        }
        Rows gaps = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        Iterator<AddressRange> ranges = gapsSet.getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            if (!gaps.open()) {
                gaps.skip();
                continue;
            }
            AddressSet one = new AddressSet(range);
            InstructionIterator code = listing.getInstructions(one, true);
            Instruction first = null;
            Instruction substantive = null;
            int scanned = 0;
            while (code.hasNext() && substantive == null && scanned < GAP_SCAN_INSTRUCTIONS) {
                Instruction instruction = code.next();
                scanned++;
                if (first == null) {
                    first = instruction;
                }
                String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
                if (!PADDING_MNEMONICS.contains(mnemonic)) {
                    substantive = instruction;
                }
            }
            gaps.add(new Obj()
                .str("end", addr(range.getMaxAddress()))
                .str("first_instruction", first == null ? "" : addr(first.getAddress()))
                .str("first_non_padding",
                    substantive == null ? "" : addr(substantive.getAddress()))
                .bool("has_defined_data", listing.getDefinedData(one, true).hasNext())
                .bool("has_instructions", first != null)
                .num("size", range.getLength())
                .str("start", addr(range.getMinAddress()))
                .done());
        }
        facts.raw("code_gaps", gaps.json());

        Rows comments = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        appendComments(listing.getCommentAddressIterator(memory, true), comments);
        facts.raw("comments", comments.json());

        Rows dataItems = new Rows(ROW_MAX, SECTION_BYTES_LARGE);
        DataIterator dataIt = listing.getDefinedData(true);
        while (dataIt.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Data data = dataIt.next();
            if (!dataItems.open()) {
                dataItems.skip();
                continue;
            }
            dataItems.add(new Obj()
                .str("address", addr(data.getAddress()))
                .str("label", data.getLabel() == null ? "" : data.getLabel())
                .num("length", data.getLength())
                .num("references_to", refs.getReferenceCountTo(data.getAddress()))
                .str("type", data.getDataType().getName())
                .str("value", clip(data.getDefaultValueRepresentation()))
                .done());
        }
        facts.raw("data_items", dataItems.json());

        Rows entries = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        AddressIterator entryIt = symbols.getExternalEntryPointIterator();
        while (entryIt.hasNext()) {
            Address entry = entryIt.next();
            Symbol primary = symbols.getPrimarySymbol(entry);
            entries.add(new Obj()
                .str("address", addr(entry))
                .bool("is_function",
                    currentProgram.getFunctionManager().getFunctionAt(entry) != null)
                .str("name", primary == null ? "" : primary.getName())
                .done());
        }
        facts.raw("entry_points", entries.json());

        Rows externals = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        ExternalManager externalManager = currentProgram.getExternalManager();
        for (String library : externalManager.getExternalLibraryNames()) {
            String libraryPath = externalManager.getExternalLibraryPath(library);
            ExternalLocationIterator locations = externalManager.getExternalLocations(library);
            while (locations.hasNext()) {
                ExternalLocation location = locations.next();
                if (!externals.open()) {
                    externals.skip();
                    continue;
                }
                externals.add(new Obj()
                    .str("address", addr(location.getAddress()))
                    .str("external_address", addr(location.getExternalSpaceAddress()))
                    .bool("is_function", location.isFunction())
                    .str("label", location.getLabel())
                    .str("library", library)
                    .str("library_path", libraryPath == null ? "" : libraryPath)
                    .str("original_name", location.getOriginalImportedName() == null ? ""
                        : location.getOriginalImportedName())
                    .str("source", String.valueOf(location.getSource()))
                    .done());
            }
        }
        facts.raw("external_locations", externals.json());

        Rows docs = new Rows(ROW_MAX, SECTION_BYTES_LARGE);
        FunctionIterator docIt = currentProgram.getFunctionManager().getFunctions(true);
        while (docIt.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Function fn = docIt.next();
            if (!docs.open()) {
                docs.skip();
                continue;
            }
            docs.add(functionDocJson(fn));
        }
        facts.raw("function_docs", docs.json());

        FunctionTagManager tagManager =
            currentProgram.getFunctionManager().getFunctionTagManager();
        Rows tags = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        for (FunctionTag tag : tagManager.getAllFunctionTags()) {
            tags.add(new Obj()
                .str("comment", clip(tag.getComment()))
                .str("name", tag.getName())
                .num("use_count", tagManager.getUseCount(tag))
                .done());
        }
        facts.raw("function_tags", tags.json());
        facts.raw("namespaces", namespaces.json());
        facts.raw("option_groups", groups.json());
        facts.raw("options", options.json());

        Obj project = new Obj();
        Project current = getState().getProject();
        Rows files = new Rows(ROW_MAX, SECTION_BYTES_SMALL);
        Rows folders = new Rows(ROW_MAX, SECTION_BYTES_TINY);
        if (current != null) {
            walkFolder(current.getProjectData().getRootFolder(), files, folders, 0);
        }
        project.bool("available", current != null)
            .raw("files", files.json())
            .raw("folders", folders.json())
            .str("name", current == null ? "" : current.getName())
            .str("program_path", currentProgram.getDomainFile() == null ? ""
                : currentProgram.getDomainFile().getPathname());
        facts.raw("project", project.done());

        PropertyMapManager propertyManager = currentProgram.getUsrPropertyManager();
        Rows maps = new Rows(ROW_MAX, SECTION_BYTES_TINY);
        Rows properties = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        Iterator<String> mapNames = propertyManager.propertyManagers();
        while (mapNames.hasNext()) {
            String name = mapNames.next();
            PropertyMap<?> map = propertyManager.getPropertyMap(name);
            if (map == null) {
                continue;
            }
            maps.add(new Obj()
                .str("name", name)
                .num("size", map.getSize())
                .str("value_class", map.getValueClass() == null ? "void"
                    : map.getValueClass().getSimpleName())
                .done());
            AddressIterator at = map.getPropertyIterator();
            while (at.hasNext()) {
                Address address = at.next();
                if (!properties.open()) {
                    properties.skip();
                    continue;
                }
                properties.add(new Obj()
                    .str("address", addr(address))
                    .str("map", name)
                    .str("value", clip(String.valueOf(map.get(address))))
                    .done());
            }
        }
        facts.raw("properties", properties.json());
        facts.raw("property_maps", maps.json());
        json.append(",\"program_facts\":").append(facts.done());
    }

    private String functionDocJson(Function fn) {
        int defaultNamed = 0;
        int undefinedTyped = 0;
        Parameter[] parameters = fn.getParameters();
        for (Parameter parameter : parameters) {
            if (parameter.getName().matches("param_\\d+")) {
                defaultNamed++;
            }
            if (isUndefined(parameter.getDataType())) {
                undefinedTyped++;
            }
        }
        Variable[] locals = fn.getLocalVariables();
        for (Variable local : locals) {
            if (isUndefined(local.getDataType())) {
                undefinedTyped++;
            }
        }
        int commentAddresses = 0;
        AddressIterator commented =
            currentProgram.getListing().getCommentAddressIterator(fn.getBody(), true);
        while (commented.hasNext() && commentAddresses < COMMENT_COUNT_SCAN_MAX) {
            commented.next();
            commentAddresses++;
        }
        List<String> tagNames = new ArrayList<>();
        for (FunctionTag tag : fn.getTags()) {
            tagNames.add(tag.getName());
        }
        java.util.Collections.sort(tagNames);
        return new Obj()
            .str("address", addr(fn.getEntryPoint()))
            .num("body_size", fn.getBody().getNumAddresses())
            .str("classification", classification(fn))
            .num("comment_addresses", commentAddresses)
            .num("default_named_parameters", defaultNamed)
            .num("local_count", locals.length)
            .str("name", fn.getName())
            .str("name_source", String.valueOf(fn.getSymbol().getSource()))
            .num("parameter_count", parameters.length)
            .bool("plate_comment", fn.getComment() != null)
            .bool("repeatable_comment", fn.getRepeatableComment() != null)
            .str("return_type", fn.getReturnType() == null ? "" : fn.getReturnType().getName())
            .str("signature", fn.getSignature().toString())
            .str("signature_source", String.valueOf(fn.getSignatureSource()))
            .raw("tags", quotedArray(tagNames))
            .num("undefined_typed_variables", undefinedTyped)
            .done();
    }

    private void walkFolder(DomainFolder folder, Rows files, Rows folders, int depth) {
        folders.add(new Obj().str("path", folder.getPathname()).done());
        for (DomainFile file : folder.getFiles()) {
            files.add(new Obj()
                .str("content_type", file.getContentType())
                .str("path", file.getPathname())
                .bool("read_only", file.isReadOnly())
                .num("version", file.getVersion())
                .done());
        }
        if (depth >= 16) {
            return;
        }
        for (DomainFolder child : folder.getFolders()) {
            walkFolder(child, files, folders, depth + 1);
        }
    }

    // ---- types: the program's data type manager plus built-ins.

    private void appendTypes(StringBuilder json) {
        DataTypeManager manager = currentProgram.getDataTypeManager();
        Rows categories = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        walkCategory(manager.getRootCategory(), categories, 0);
        Rows types = new Rows(ROW_MAX, 4L * SECTION_BYTES_LARGE);
        Iterator<DataType> all = manager.getAllDataTypes();
        while (all.hasNext()) {
            DataType type = all.next();
            if (!types.open()) {
                types.skip();
                continue;
            }
            types.add(dataTypeJson(type));
        }
        Rows builtins = new Rows(ROW_MAX, SECTION_BYTES_MEDIUM);
        Iterator<DataType> builtIn = BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes();
        while (builtIn.hasNext()) {
            DataType type = builtIn.next();
            builtins.add(new Obj().num("length", type.getLength()).str("name", type.getName())
                .done());
        }
        json.append(",\"types\":").append(new Obj()
            .raw("builtins", builtins.json())
            .raw("categories", categories.json())
            .raw("data_types", types.json())
            .num("pointer_size", manager.getDataOrganization().getPointerSize())
            .done());
    }

    private void walkCategory(Category category, Rows rows, int depth) {
        rows.add(new Obj()
            .num("data_type_count", category.getDataTypes().length)
            .str("path", category.getCategoryPathName())
            .num("subcategory_count", category.getCategories().length)
            .done());
        if (depth >= 32) {
            return;
        }
        for (Category child : category.getCategories()) {
            walkCategory(child, rows, depth + 1);
        }
    }

    private static String dataTypeJson(DataType type) {
        Obj row = new Obj()
            .num("alignment", type.getAlignment())
            .str("category", type.getCategoryPath().getPath())
            .str("description", clip(type.getDescription()))
            .str("kind", dataTypeKind(type))
            .num("length", type.getLength())
            .str("name", type.getName())
            .str("path", type.getPathName());
        if (type instanceof Composite) {
            Rows components = new Rows(COMPONENT_MAX, SECTION_BYTES_TINY);
            for (DataTypeComponent component : ((Composite) type).getDefinedComponents()) {
                components.add(new Obj()
                    .str("comment", clip(component.getComment()))
                    .num("length", component.getLength())
                    .str("name", component.getFieldName() == null ? ""
                        : component.getFieldName())
                    .num("offset", component.getOffset())
                    .str("type", component.getDataType().getName())
                    .done());
            }
            row.raw("components", components.json());
        } else if (type instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum values = (ghidra.program.model.data.Enum) type;
            Rows rows = new Rows(COMPONENT_MAX, SECTION_BYTES_TINY);
            for (String name : values.getNames()) {
                rows.add(new Obj().str("name", name).num("value", values.getValue(name)).done());
            }
            row.raw("values", rows.json());
        } else if (type instanceof TypeDef) {
            row.str("base", ((TypeDef) type).getBaseDataType().getName());
        } else if (type instanceof Pointer) {
            DataType target = ((Pointer) type).getDataType();
            row.str("base", target == null ? "void" : target.getName());
        } else if (type instanceof Array) {
            Array array = (Array) type;
            row.str("base", array.getDataType().getName())
                .num("element_count", array.getNumElements());
        } else if (type instanceof FunctionDefinition) {
            row.str("prototype", ((FunctionDefinition) type).getPrototypeString());
        }
        return row.done();
    }

    private static String dataTypeKind(DataType type) {
        if (type instanceof Structure) {
            return "structure";
        }
        if (type instanceof Union) {
            return "union";
        }
        if (type instanceof ghidra.program.model.data.Enum) {
            return "enum";
        }
        if (type instanceof TypeDef) {
            return "typedef";
        }
        if (type instanceof Pointer) {
            return "pointer";
        }
        if (type instanceof Array) {
            return "array";
        }
        if (type instanceof FunctionDefinition) {
            return "function_definition";
        }
        if (type instanceof ghidra.program.model.data.BuiltInDataType) {
            return "builtin";
        }
        return "other";
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
