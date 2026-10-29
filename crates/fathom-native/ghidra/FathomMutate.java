// FathomMutate.java -- transactional headless mutation for fathom (SPEC 9.1, G2).
//
// Run by analyzeHeadless as a -postScript against a COPY of the
// cached project (the Rust engine owns copy/commit/discard). Script
// argument 1 is the ops file, argument 2 the result file.
//
// Ops file: one op per line, fields tab-separated, every field
// Base64 (UTF-8) so caller text can never smuggle a separator or a
// newline. The whole batch runs in ONE Ghidra transaction: any op
// failure or failed postcondition ends the transaction with
// commit=false, so Ghidra itself discards every change, and the
// result file says "rolled_back". On success the transaction
// commits and the program is saved; the result file says
// "committed" with one verified postcondition string per op.
//
// The grammar is deliberately bounded: names, addresses, type
// names, comment/bookmark text, simple C prototypes (named scalar
// or pointer parameters). No arbitrary script execution exists in
// this surface by design.
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class FathomMutate extends GhidraScript {

    private static final int OPS_MAX = 256;
    private static final int CLEAR_UNITS_MAX = 100000;

    private Listing listing;
    private SymbolTable symbols;
    private DataTypeManager dtm;
    private BookmarkManager bookmarks;

    private static String dec(String field) {
        return new String(Base64.getDecoder().decode(field), StandardCharsets.UTF_8);
    }

    private static String esc(String text) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"') {
                out.append("\\\"");
            } else if (c == '\\') {
                out.append("\\\\");
            } else if (c < 0x20) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private Address addr(String hex) throws Exception {
        Address a = currentProgram.getAddressFactory().getAddress(hex.trim());
        if (a == null) {
            throw new Exception("unparsable address: " + hex);
        }
        return a;
    }

    private Function functionAt(String hex) throws Exception {
        Function fn = getFunctionAt(addr(hex));
        if (fn == null) {
            fn = getFunctionContaining(addr(hex));
        }
        if (fn == null) {
            throw new Exception("no function at " + hex);
        }
        return fn;
    }

    private DataType resolveType(String text) throws Exception {
        String name = text.trim();
        int stars = 0;
        while (name.endsWith("*")) {
            stars++;
            name = name.substring(0, name.length() - 1).trim();
        }
        int arrayCount = -1;
        if (name.endsWith("]")) {
            int open = name.lastIndexOf('[');
            if (open < 0) {
                throw new Exception("bad array type: " + text);
            }
            arrayCount = Integer.parseInt(name.substring(open + 1, name.length() - 1).trim());
            name = name.substring(0, open).trim();
        }
        DataType base = dtm.getDataType(new CategoryPath("/"), name);
        if (base == null) {
            Iterator<DataType> it = dtm.getAllDataTypes();
            while (it.hasNext()) {
                DataType candidate = it.next();
                if (candidate.getName().equals(name)) {
                    base = candidate;
                    break;
                }
            }
        }
        if (base == null) {
            throw new Exception("unknown data type: " + text);
        }
        DataType result = base;
        if (arrayCount >= 0) {
            result = new ArrayDataType(base, arrayCount, base.getLength());
        }
        for (int i = 0; i < stars; i++) {
            result = new PointerDataType(result);
        }
        return result;
    }

    private DataType findType(String name) throws Exception {
        return resolveType(name);
    }

    private Structure findStruct(String name) throws Exception {
        DataType dt = findType(name);
        if (!(dt instanceof Structure)) {
            throw new Exception("not a structure: " + name);
        }
        return (Structure) dt;
    }

    private CommentType commentType(String name) throws Exception {
        switch (name.trim().toLowerCase()) {
            case "eol": return CommentType.EOL;
            case "plate": return CommentType.PLATE;
            case "post": return CommentType.POST;
            case "pre": return CommentType.PRE;
            case "repeatable": return CommentType.REPEATABLE;
            // The decompiler renders EOL/PRE comments; Ghidra 12
            // stores no sixth comment kind, so the decompiler
            // comment class is the EOL comment (adjudicated in the
            // G2 differential against the bridge).
            case "decompiler": return CommentType.EOL;
            case "disassembly": return CommentType.EOL;
            default: throw new Exception("unknown comment type: " + name);
        }
    }

    private Variable findVariable(Function fn, String varName) throws Exception {
        for (Variable v : fn.getAllVariables()) {
            if (v.getName().equals(varName)) {
                return v;
            }
        }
        throw new Exception("no variable '" + varName + "' in " + fn.getName());
    }

    /** Apply one op; return its verified postcondition string. */
    private String apply(String[] f) throws Exception {
        String op = f[0];
        switch (op) {
            case "rename_function": {
                Function fn = functionAt(f[1]);
                fn.setName(f[2], SourceType.USER_DEFINED);
                String now = functionAt(f[1]).getName();
                if (!now.equals(f[2])) {
                    throw new Exception("postcondition: function name is " + now);
                }
                return "function@" + f[1] + "=" + now;
            }
            case "rename_symbol": {
                Address a = addr(f[1]);
                Symbol s = symbols.getPrimarySymbol(a);
                if (s == null) {
                    throw new Exception("no primary symbol at " + f[1]);
                }
                s.setName(f[2], SourceType.USER_DEFINED);
                Symbol now = symbols.getPrimarySymbol(a);
                if (now == null || !now.getName().equals(f[2])) {
                    throw new Exception("postcondition: symbol rename failed");
                }
                return "symbol@" + f[1] + "=" + f[2];
            }
            case "create_label": {
                Address a = addr(f[1]);
                Symbol s = symbols.createLabel(a, f[2], currentProgram.getGlobalNamespace(),
                    SourceType.USER_DEFINED);
                if (s == null) {
                    throw new Exception("postcondition: label not created");
                }
                return "label@" + f[1] + "=" + f[2];
            }
            case "delete_label": {
                Address a = addr(f[1]);
                Symbol[] found = symbols.getSymbols(a);
                boolean removed = false;
                for (Symbol s : found) {
                    if (s.getName().equals(f[2])) {
                        removed = s.delete() || removed;
                    }
                }
                for (Symbol s : symbols.getSymbols(a)) {
                    if (s.getName().equals(f[2])) {
                        throw new Exception("postcondition: label still present");
                    }
                }
                if (!removed) {
                    throw new Exception("no label '" + f[2] + "' at " + f[1]);
                }
                return "label@" + f[1] + "!=deleted";
            }
            case "rename_variable": {
                Function fn = functionAt(f[1]);
                Variable v = findVariable(fn, f[2]);
                v.setName(f[3], SourceType.USER_DEFINED);
                findVariable(fn, f[3]);
                return "variable@" + f[1] + "=" + f[3];
            }
            case "set_comment": {
                Address a = addr(f[1]);
                CommentType type = commentType(f[2]);
                listing.setComment(a, type, f[3]);
                String now = listing.getComment(type, a);
                if (now == null || !now.equals(f[3])) {
                    throw new Exception("postcondition: comment mismatch");
                }
                return "comment@" + f[1] + ":" + f[2];
            }
            case "clear_function_comments": {
                Function fn = functionAt(f[1]);
                CodeUnitIterator it = listing.getCodeUnits(fn.getBody(), true);
                int seen = 0;
                while (it.hasNext() && seen < CLEAR_UNITS_MAX) {
                    CodeUnit cu = it.next();
                    for (CommentType t : CommentType.values()) {
                        cu.setComment(t, null);
                    }
                    seen++;
                }
                String atEntry = listing.getComment(CommentType.EOL, fn.getEntryPoint());
                if (atEntry != null) {
                    throw new Exception("postcondition: entry comment remains");
                }
                return "comments_cleared@" + f[1];
            }
            case "set_bookmark": {
                Address a = addr(f[1]);
                bookmarks.setBookmark(a, f[2], f[3], f[4]);
                Bookmark b = bookmarks.getBookmark(a, f[2], f[3]);
                if (b == null) {
                    throw new Exception("postcondition: bookmark missing");
                }
                return "bookmark@" + f[1] + ":" + f[3];
            }
            case "delete_bookmark": {
                Address a = addr(f[1]);
                Bookmark b = bookmarks.getBookmark(a, f[2], f[3]);
                if (b == null) {
                    throw new Exception("no bookmark '" + f[3] + "' at " + f[1]);
                }
                bookmarks.removeBookmark(b);
                if (bookmarks.getBookmark(a, f[2], f[3]) != null) {
                    throw new Exception("postcondition: bookmark remains");
                }
                return "bookmark@" + f[1] + "!=deleted";
            }
            case "set_function_prototype": {
                Function fn = functionAt(f[1]);
                String[] parsed = parsePrototype(f[2]);
                fn.setReturnType(resolveType(parsed[0]), SourceType.USER_DEFINED);
                List<Variable> params = new ArrayList<>();
                if (!parsed[2].isEmpty()) {
                    for (String p : parsed[2].split(";")) {
                        String[] nv = p.split("=", 2);
                        params.add(new ParameterImpl(nv[0], resolveType(nv[1]),
                            currentProgram));
                    }
                }
                fn.replaceParameters(params,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.USER_DEFINED);
                Function now = functionAt(f[1]);
                if (!now.getReturnType().getName().equals(resolveType(parsed[0]).getName())) {
                    throw new Exception("postcondition: return type mismatch");
                }
                if (now.getParameterCount() != params.size()) {
                    throw new Exception("postcondition: parameter count mismatch");
                }
                return "prototype@" + f[1] + "=" + now.getSignature().getPrototypeString();
            }
            case "set_parameter_type": {
                Function fn = functionAt(f[1]);
                int idx = Integer.parseInt(f[2]);
                Parameter[] ps = fn.getParameters();
                if (idx < 0 || idx >= ps.length) {
                    throw new Exception("parameter index out of range: " + f[2]);
                }
                DataType dt = resolveType(f[3]);
                ps[idx].setDataType(dt, SourceType.USER_DEFINED);
                String now = functionAt(f[1]).getParameters()[idx].getDataType().getName();
                if (!now.equals(dt.getName())) {
                    throw new Exception("postcondition: parameter type is " + now);
                }
                return "parameter@" + f[1] + "[" + f[2] + "]=" + now;
            }
            case "set_variable_type": {
                Function fn = functionAt(f[1]);
                Variable v = findVariable(fn, f[2]);
                DataType dt = resolveType(f[3]);
                v.setDataType(dt, SourceType.USER_DEFINED);
                String now = findVariable(functionAt(f[1]), f[2]).getDataType().getName();
                if (!now.equals(dt.getName())) {
                    throw new Exception("postcondition: variable type is " + now);
                }
                return "variable_type@" + f[1] + "=" + now;
            }
            case "apply_data_type": {
                Address a = addr(f[1]);
                DataType dt = resolveType(f[2]);
                Data existing = listing.getDataAt(a);
                if (existing != null && existing.isDefined()) {
                    listing.clearCodeUnits(a, a, false);
                }
                createData(a, dt);
                Data now = listing.getDataAt(a);
                if (now == null || !now.getDataType().getName().equals(dt.getName())) {
                    throw new Exception("postcondition: data type not applied");
                }
                return "data@" + f[1] + "=" + dt.getName();
            }
            case "create_struct": {
                StructureDataType s = new StructureDataType(
                    new CategoryPath("/"), f[1], 0, dtm);
                if (!f[2].isEmpty()) {
                    for (String field : f[2].split(";")) {
                        String[] nv = field.split("=", 2);
                        DataType ft = resolveType(nv[1]);
                        s.add(ft, ft.getLength(), nv[0], null);
                    }
                }
                DataType added = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
                Structure now = (Structure) dtm.getDataType(added.getDataTypePath());
                if (now == null || now.getNumComponents() != s.getNumComponents()) {
                    throw new Exception("postcondition: struct mismatch");
                }
                return "struct=" + f[1] + ":" + now.getLength();
            }
            case "create_union": {
                UnionDataType u = new UnionDataType(new CategoryPath("/"), f[1]);
                if (!f[2].isEmpty()) {
                    for (String field : f[2].split(";")) {
                        String[] nv = field.split("=", 2);
                        DataType ft = resolveType(nv[1]);
                        u.add(ft, nv[0], null);
                    }
                }
                dtm.addDataType(u, DataTypeConflictHandler.REPLACE_HANDLER);
                return "union=" + f[1];
            }
            case "add_struct_field": {
                Structure s = findStruct(f[1]);
                DataType ft = resolveType(f[3]);
                s.add(ft, ft.getLength(), f[2], null);
                Structure now = findStruct(f[1]);
                if (now.findComponent(f[2]) == null) {
                    throw new Exception("postcondition: field missing");
                }
                return "struct_field=" + f[1] + "." + f[2];
            }
            case "modify_struct_field": {
                Structure s = findStruct(f[1]);
                DataTypeComponent comp = s.findComponent(f[2]);
                if (comp == null) {
                    throw new Exception("no field '" + f[2] + "' in " + f[1]);
                }
                DataType nt = resolveType(f[3]);
                s.replace(comp.getOrdinal(), nt, nt.getLength(),
                    comp.getFieldName(), comp.getComment());
                DataTypeComponent now = findStruct(f[1]).findComponent(f[2]);
                if (now == null || !now.getDataType().getName().equals(nt.getName())) {
                    throw new Exception("postcondition: field type mismatch");
                }
                return "struct_field_type=" + f[1] + "." + f[2] + "=" + nt.getName();
            }
            case "remove_struct_field": {
                Structure s = findStruct(f[1]);
                DataTypeComponent comp = s.findComponent(f[2]);
                if (comp == null) {
                    throw new Exception("no field '" + f[2] + "' in " + f[1]);
                }
                s.deleteAtOffset(comp.getOffset());
                if (findStruct(f[1]).findComponent(f[2]) != null) {
                    throw new Exception("postcondition: field remains");
                }
                return "struct_field!=" + f[1] + "." + f[2];
            }
            case "create_enum": {
                int size = 4;
                List<String[]> entries = new ArrayList<>();
                if (!f[2].isEmpty()) {
                    for (String e : f[2].split(";")) {
                        String[] nv = e.split("=", 2);
                        long v = Long.parseLong(nv[1]);
                        if (v > 0xFFFFFFFFL || v < Integer.MIN_VALUE) {
                            size = 8;
                        }
                        entries.add(new String[]{nv[0], nv[1]});
                    }
                }
                EnumDataType en = new EnumDataType(new CategoryPath("/"), f[1], size);
                for (String[] e : entries) {
                    en.add(e[0], Long.parseLong(e[1]));
                }
                dtm.addDataType(en, DataTypeConflictHandler.REPLACE_HANDLER);
                if (findType(f[1]) == null) {
                    throw new Exception("postcondition: enum missing");
                }
                return "enum=" + f[1] + ":" + entries.size();
            }
            case "create_typedef": {
                DataType base = resolveType(f[2]);
                TypedefDataType td = new TypedefDataType(
                    new CategoryPath("/"), f[1], base);
                dtm.addDataType(td, DataTypeConflictHandler.REPLACE_HANDLER);
                return "typedef=" + f[1];
            }
            case "create_pointer_type": {
                DataType ptr = new PointerDataType(resolveType(f[1]));
                DataType added = dtm.addDataType(ptr, DataTypeConflictHandler.REPLACE_HANDLER);
                return "pointer=" + added.getName();
            }
            case "create_array_type": {
                DataType base = resolveType(f[1]);
                int count = Integer.parseInt(f[2]);
                DataType arr = new ArrayDataType(base, count, base.getLength());
                DataType added = dtm.addDataType(arr, DataTypeConflictHandler.REPLACE_HANDLER);
                return "array=" + added.getName();
            }
            case "clone_data_type": {
                DataType src = findType(f[1]);
                DataType copy = src.clone(dtm);
                copy.setName(f[2]);
                dtm.addDataType(copy, DataTypeConflictHandler.REPLACE_HANDLER);
                if (findType(f[2]) == null) {
                    throw new Exception("postcondition: clone missing");
                }
                return "clone=" + f[2];
            }
            case "rename_data_type": {
                DataType dt = findType(f[1]);
                dt.setName(f[2]);
                if (!findType(f[2]).getName().equals(f[2])) {
                    throw new Exception("postcondition: type rename failed");
                }
                return "data_type=" + f[2];
            }
            case "delete_data_type": {
                DataType dt = findType(f[1]);
                dtm.remove(dt);
                return "data_type!=deleted:" + f[1];
            }
            case "create_data_type_category": {
                CategoryPath path = new CategoryPath(f[1]);
                dtm.createCategory(path);
                if (dtm.getCategory(path) == null) {
                    throw new Exception("postcondition: category missing");
                }
                return "category=" + f[1];
            }
            case "move_data_type_to_category": {
                DataType dt = findType(f[1]);
                CategoryPath path = new CategoryPath(f[2]);
                if (dtm.getCategory(path) == null) {
                    dtm.createCategory(path);
                }
                dt.setCategoryPath(path);
                if (!findType(f[1]).getCategoryPath().equals(path)) {
                    throw new Exception("postcondition: category mismatch");
                }
                return "category_of=" + f[1] + ":" + f[2];
            }
            case "create_function_signature": {
                String[] parsed = parsePrototype(f[2]);
                FunctionDefinitionDataType fd = new FunctionDefinitionDataType(f[1]);
                fd.setReturnType(resolveType(parsed[0]));
                List<ParameterDefinition> defs = new ArrayList<>();
                if (!parsed[2].isEmpty()) {
                    for (String p : parsed[2].split(";")) {
                        String[] nv = p.split("=", 2);
                        defs.add(new ParameterDefinitionImpl(nv[0], resolveType(nv[1]), null));
                    }
                }
                fd.setArguments(defs.toArray(new ParameterDefinition[0]));
                dtm.addDataType(fd, DataTypeConflictHandler.REPLACE_HANDLER);
                return "signature=" + f[1];
            }
            case "add_function_tag": {
                Function fn = functionAt(f[1]);
                if (!fn.addTag(f[2])) {
                    // addTag returns false when the tag is new-created
                    // in some versions; verify by membership instead.
                    boolean present = false;
                    for (ghidra.program.model.listing.FunctionTag t : fn.getTags()) {
                        if (t.getName().equals(f[2])) {
                            present = true;
                        }
                    }
                    if (!present) {
                        throw new Exception("postcondition: tag not on function");
                    }
                }
                return "tag@" + f[1] + "=" + f[2];
            }
            case "remove_function_tag": {
                Function fn = functionAt(f[1]);
                fn.removeTag(f[2]);
                for (ghidra.program.model.listing.FunctionTag t : fn.getTags()) {
                    if (t.getName().equals(f[2])) {
                        throw new Exception("postcondition: tag remains");
                    }
                }
                return "tag@" + f[1] + "!=removed";
            }
            case "create_function_tag": {
                FunctionTagManager mgr = currentProgram.getFunctionManager()
                    .getFunctionTagManager();
                FunctionTag tag = mgr.createFunctionTag(f[1], f[2]);
                if (tag == null || mgr.getFunctionTag(f[1]) == null) {
                    throw new Exception("postcondition: tag not created");
                }
                return "function_tag=" + f[1];
            }
            case "set_function_tag_comment": {
                FunctionTagManager mgr = currentProgram.getFunctionManager()
                    .getFunctionTagManager();
                FunctionTag tag = mgr.getFunctionTag(f[1]);
                if (tag == null) {
                    throw new Exception("no function tag '" + f[1] + "'");
                }
                tag.setComment(f[2]);
                if (!f[2].equals(mgr.getFunctionTag(f[1]).getComment())) {
                    throw new Exception("postcondition: tag comment mismatch");
                }
                return "function_tag_comment=" + f[1];
            }
            case "set_function_no_return": {
                Function fn = functionAt(f[1]);
                fn.setNoReturn(true);
                if (!functionAt(f[1]).hasNoReturn()) {
                    throw new Exception("postcondition: no-return not set");
                }
                return "no_return@" + f[1];
            }
            case "create_function": {
                Address a = addr(f[1]);
                Function fn = createFunction(a, f[2]);
                if (fn == null) {
                    fn = getFunctionAt(a);
                }
                if (fn == null) {
                    throw new Exception("postcondition: function not created");
                }
                return "function_created@" + f[1] + "=" + fn.getName();
            }
            case "delete_function": {
                Address a = addr(f[1]);
                if (getFunctionAt(a) == null) {
                    throw new Exception("no function at " + f[1]);
                }
                removeFunction(getFunctionAt(a));
                if (getFunctionAt(a) != null) {
                    throw new Exception("postcondition: function remains");
                }
                return "function!=deleted:" + f[1];
            }
            case "add_memory_reference": {
                Address from = addr(f[1]);
                Address to = addr(f[2]);
                RefType type = refType(f[3]);
                currentProgram.getReferenceManager().addMemoryReference(
                    from, to, type, SourceType.USER_DEFINED, 0);
                if (!hasReference(from, to)) {
                    throw new Exception("postcondition: reference missing");
                }
                return "reference=" + f[1] + "->" + f[2];
            }
            case "remove_reference": {
                Address from = addr(f[1]);
                Address to = addr(f[2]);
                boolean removed = false;
                Reference[] fromRefs = currentProgram.getReferenceManager()
                    .getReferencesFrom(from);
                List<Reference> doomed = new ArrayList<>();
                for (Reference r : fromRefs) {
                    if (r.getToAddress().equals(to)) {
                        doomed.add(r);
                    }
                }
                for (Reference r : doomed) {
                    currentProgram.getReferenceManager().delete(r);
                    removed = true;
                }
                if (!removed) {
                    throw new Exception("no reference " + f[1] + " -> " + f[2]);
                }
                if (hasReference(from, to)) {
                    throw new Exception("postcondition: reference remains");
                }
                return "reference!=removed:" + f[1] + "->" + f[2];
            }
            default:
                throw new Exception("unknown op: " + op);
        }
    }

    private boolean hasReference(Address from, Address to) {
        Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(from);
        for (Reference r : refs) {
            if (r.getToAddress().equals(to)) {
                return true;
            }
        }
        return false;
    }

    private RefType refType(String name) throws Exception {
        switch (name.trim().toUpperCase()) {
            case "DATA": return RefType.DATA;
            case "READ": return RefType.READ;
            case "WRITE": return RefType.WRITE;
            case "INDIRECTION": return RefType.INDIRECTION;
            case "UNCONDITIONAL_CALL": return RefType.UNCONDITIONAL_CALL;
            case "UNCONDITIONAL_JUMP": return RefType.UNCONDITIONAL_JUMP;
            case "CONDITIONAL_JUMP": return RefType.CONDITIONAL_JUMP;
            default: throw new Exception("unknown reference type: " + name);
        }
    }

    /** Parse "ret name(type p1, type p2)" -> [ret, name, "p1=type;p2=type"]. */
    private String[] parsePrototype(String proto) throws Exception {
        String text = proto.trim();
        int lp = text.indexOf('(');
        int rp = text.lastIndexOf(')');
        if (lp < 0 || rp < lp) {
            throw new Exception("bad prototype: " + proto);
        }
        String head = text.substring(0, lp).trim();
        String paramsText = text.substring(lp + 1, rp).trim();
        int lastSpace = head.lastIndexOf(' ');
        if (lastSpace < 0) {
            throw new Exception("prototype needs a return type and a name: " + proto);
        }
        String name = head.substring(lastSpace + 1).trim();
        String ret = head.substring(0, lastSpace).trim();
        while (name.startsWith("*")) {
            name = name.substring(1);
            ret = ret + " *";
        }
        List<String> params = new ArrayList<>();
        if (!paramsText.isEmpty() && !paramsText.equals("void")) {
            for (String raw : paramsText.split(",")) {
                String p = raw.trim();
                int sp = p.lastIndexOf(' ');
                if (sp < 0) {
                    params.add("=" + p);
                } else {
                    String pname = p.substring(sp + 1).trim();
                    String ptype = p.substring(0, sp).trim();
                    while (pname.startsWith("*")) {
                        pname = pname.substring(1);
                        ptype = ptype + " *";
                    }
                    params.add(pname + "=" + ptype);
                }
            }
        }
        return new String[]{ret, name, String.join(";", params)};
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new Exception("usage: FathomMutate <opsFile> <resultFile>");
        }
        File opsFile = new File(args[0]);
        File resultFile = new File(args[1]);
        List<String[]> ops = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new FileReader(opsFile, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                if (ops.size() >= OPS_MAX) {
                    writeResult(resultFile, "rolled_back", ops.size(),
                        "batch exceeds the " + OPS_MAX + "-op bound");
                    return;
                }
                String[] raw = line.split("\t", -1);
                String[] fields = new String[raw.length];
                for (int i = 0; i < raw.length; i++) {
                    fields[i] = dec(raw[i]);
                }
                ops.add(fields);
            }
        }
        listing = currentProgram.getListing();
        symbols = currentProgram.getSymbolTable();
        dtm = currentProgram.getDataTypeManager();
        bookmarks = currentProgram.getBookmarkManager();

        List<String> verified = new ArrayList<>();
        String error = null;
        int tx = currentProgram.startTransaction("fathom-mutation");
        boolean commit = false;
        try {
            for (String[] fields : ops) {
                verified.add(apply(fields));
            }
            commit = true;
        } catch (Exception e) {
            error = String.valueOf(e.getMessage());
        } finally {
            currentProgram.endTransaction(tx, commit);
        }
        if (commit) {
            // No save() here: analyzeHeadless runs scripts inside
            // its own transaction and refuses a nested save
            // ("Unable to lock due to active transaction"); the
            // analyzer saves a changed program itself after the
            // script completes -- the Rust engine verifies that by
            // re-export, never by trusting this result alone.
            StringBuilder sb = new StringBuilder();
            sb.append("{\"status\":\"committed\",\"applied\":").append(verified.size());
            sb.append(",\"verified\":[");
            for (int i = 0; i < verified.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append("\"").append(esc(verified.get(i))).append("\"");
            }
            sb.append("]}");
            writeRaw(resultFile, sb.toString());
        } else {
            writeResult(resultFile, "rolled_back", 0,
                error == null ? "unknown failure" : error);
        }
    }

    private void writeResult(File file, String status, int applied, String error)
            throws Exception {
        writeRaw(file, "{\"status\":\"" + status + "\",\"applied\":" + applied
            + ",\"error\":\"" + esc(error) + "\"}");
    }

    private void writeRaw(File file, String text) throws Exception {
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(file, StandardCharsets.UTF_8))) {
            writer.write(text);
        }
    }
}
