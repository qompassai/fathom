//! Per-module static analysis with oxc (SPEC §9.2).
//!
//! Facts only: imports (ESM and `require`), exports, and the
//! Electron boundary — IPC channels by direction, `contextBridge`
//! exposures, and `BrowserWindow` web preferences. Local names
//! are resolved through import/`require` aliases so destructured
//! Electron APIs are recognized; a call the analyzer cannot
//! resolve is simply not a fact.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;

#[derive(Debug, Default, Serialize)]
pub struct BridgeExposure {
    pub keys: Vec<String>,
    pub name: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ElectronFacts {
    pub bridge_exposures: Vec<BridgeExposure>,
    pub ipc_handle: Vec<String>,
    pub ipc_invoke: Vec<String>,
    pub ipc_on: Vec<String>,
    pub ipc_send: Vec<String>,
    pub ipc_send_sync: Vec<String>,
    pub uses_electron: bool,
    pub windows: Vec<WindowFacts>,
}

#[derive(Debug, Serialize)]
pub struct ImportFact {
    pub kind: String,
    pub source: String,
    pub specifiers: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct ModuleFacts {
    pub electron: ElectronFacts,
    pub exports: Vec<String>,
    pub imports: Vec<ImportFact>,
    pub parse_errors: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct WindowFacts {
    pub context_isolation: Option<bool>,
    pub node_integration: Option<bool>,
    pub preload: Option<String>,
    pub sandbox: Option<bool>,
}

/// Analyze one module's source. Parse errors land in
/// `parse_errors`; whatever AST exists is still walked.
pub fn analyze_source(path: &Path, source: &str) -> ModuleFacts {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path).unwrap_or_default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    let mut facts = ModuleFacts::default();
    for diagnostic in &parsed.diagnostics {
        facts.parse_errors.push(diagnostic.message.to_string());
    }
    let mut collector = Collector {
        aliases: BTreeMap::new(),
        facts: ModuleFacts::default(),
    };
    collector.seed_aliases(&parsed.program);
    collector.visit_program(&parsed.program);
    facts.imports = collector.facts.imports;
    facts.exports = collector.facts.exports;
    facts.electron = collector.facts.electron;
    facts
}

struct Collector {
    /// Local name -> canonical dotted path ("electron.ipcMain").
    aliases: BTreeMap<String, String>,
    facts: ModuleFacts,
}

impl Collector {
    /// Imports hoist; seed aliases from top-level statements
    /// before the walk so call order does not matter.
    fn seed_aliases(&mut self, program: &Program) {
        for statement in &program.body {
            match statement {
                Statement::ImportDeclaration(import) => self.record_import(import),
                Statement::VariableDeclaration(declaration) => {
                    for declarator in &declaration.declarations {
                        self.record_declarator(declarator);
                    }
                }
                _ => {}
            }
        }
    }

    fn record_import(&mut self, import: &ImportDeclaration) {
        let source = import.source.value.as_str().to_string();
        let mut specifiers = Vec::new();
        if let Some(list) = &import.specifiers {
            for specifier in list {
                match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(named) => {
                        let imported = export_name(&named.imported);
                        let local = named.local.name.as_str().to_string();
                        self.aliases.insert(local, format!("{source}.{imported}"));
                        specifiers.push(imported);
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
                        self.aliases
                            .insert(default.local.name.as_str().to_string(), source.clone());
                        specifiers.push("default".to_string());
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
                        self.aliases
                            .insert(namespace.local.name.as_str().to_string(), source.clone());
                        specifiers.push("*".to_string());
                    }
                }
            }
        }
        if source == "electron" {
            self.facts.electron.uses_electron = true;
        }
        self.facts.imports.push(ImportFact {
            kind: "import".to_string(),
            source,
            specifiers,
        });
    }

    fn record_declarator(&mut self, declarator: &VariableDeclarator) {
        let Some(init) = &declarator.init else {
            return;
        };
        // const x = require('mod') / const x = require('mod').member
        let mut cursor = init;
        let mut member_chain: Vec<String> = Vec::new();
        loop {
            match cursor {
                Expression::StaticMemberExpression(member) => {
                    member_chain.push(member.property.name.as_str().to_string());
                    cursor = &member.object;
                }
                Expression::CallExpression(call) => {
                    if let Some(source) = require_source(call) {
                        member_chain.reverse();
                        let mut canonical = source.clone();
                        for segment in &member_chain {
                            canonical.push('.');
                            canonical.push_str(segment);
                        }
                        self.bind_pattern(&declarator.id, &source, &canonical);
                        if source == "electron" {
                            self.facts.electron.uses_electron = true;
                        }
                        let fact = ImportFact {
                            kind: "require".to_string(),
                            source,
                            specifiers: member_chain,
                        };
                        let duplicate = self.facts.imports.iter().any(|existing| {
                            existing.kind == fact.kind
                                && existing.source == fact.source
                                && existing.specifiers == fact.specifiers
                        });
                        if !duplicate {
                            self.facts.imports.push(fact);
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
    }

    fn bind_pattern(&mut self, pattern: &BindingPattern, source: &str, canonical: &str) {
        match pattern {
            BindingPattern::BindingIdentifier(identifier) => {
                self.aliases
                    .insert(identifier.name.as_str().to_string(), canonical.to_string());
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    if let BindingPattern::BindingIdentifier(local) = &property.value {
                        let key = property_key_name(&property.key);
                        self.aliases
                            .insert(local.name.as_str().to_string(), format!("{source}.{key}"));
                    }
                }
            }
            _ => {}
        }
    }

    /// Canonical dotted path for an expression, resolving the
    /// root through the alias table. `require('electron')` as a
    /// root resolves to `electron`.
    fn canonical(&self, expression: &Expression) -> Option<String> {
        match expression {
            Expression::Identifier(identifier) => {
                let name = identifier.name.as_str();
                Some(
                    self.aliases
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| name.to_string()),
                )
            }
            Expression::StaticMemberExpression(member) => {
                let base = self.canonical(&member.object)?;
                Some(format!("{base}.{}", member.property.name.as_str()))
            }
            Expression::CallExpression(call) => require_source(call),
            _ => None,
        }
    }
}

impl<'a> Visit<'a> for Collector {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(source) = require_source(call) {
            let already = self
                .facts
                .imports
                .iter()
                .any(|fact| fact.kind == "require" && fact.source == source);
            if !already {
                self.facts.imports.push(ImportFact {
                    kind: "require".to_string(),
                    source: source.clone(),
                    specifiers: Vec::new(),
                });
            }
            if source == "electron" {
                self.facts.electron.uses_electron = true;
            }
        }
        if let Some(path) = self.canonical(&call.callee) {
            let channel = call
                .arguments
                .first()
                .and_then(|arg| arg.as_expression())
                .and_then(string_value);
            let electron = &mut self.facts.electron;
            if path.ends_with("ipcMain.handle") {
                if let Some(channel) = channel.clone() {
                    electron.ipc_handle.push(channel);
                }
                electron.uses_electron = true;
            } else if path.ends_with("ipcMain.on") {
                if let Some(channel) = channel.clone() {
                    electron.ipc_on.push(channel);
                }
                electron.uses_electron = true;
            } else if path.ends_with("ipcRenderer.invoke") {
                if let Some(channel) = channel.clone() {
                    electron.ipc_invoke.push(channel);
                }
                electron.uses_electron = true;
            } else if path.ends_with("ipcRenderer.sendSync") {
                if let Some(channel) = channel.clone() {
                    electron.ipc_send_sync.push(channel);
                }
                electron.uses_electron = true;
            } else if path.ends_with("ipcRenderer.send") {
                if let Some(channel) = channel.clone() {
                    electron.ipc_send.push(channel);
                }
                electron.uses_electron = true;
            } else if path.ends_with("contextBridge.exposeInMainWorld") {
                electron.uses_electron = true;
                if let Some(name) = channel {
                    let keys = call
                        .arguments
                        .get(1)
                        .and_then(|arg| arg.as_expression())
                        .map(object_keys)
                        .unwrap_or_default();
                    electron
                        .bridge_exposures
                        .push(BridgeExposure { keys, name });
                }
            }
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_export_all_declaration(&mut self, export: &ExportAllDeclaration<'a>) {
        let source = export.source.value.as_str().to_string();
        self.facts.exports.push(format!("* from '{source}'"));
        self.facts.imports.push(ImportFact {
            kind: "export".to_string(),
            source,
            specifiers: vec!["*".to_string()],
        });
    }

    fn visit_export_declaration(&mut self, export: &ExportDeclaration<'a>) {
        match &export.declaration {
            Declaration::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    self.facts.exports.push(id.name.as_str().to_string());
                }
            }
            Declaration::ClassDeclaration(class) => {
                if let Some(id) = &class.id {
                    self.facts.exports.push(id.name.as_str().to_string());
                }
            }
            Declaration::VariableDeclaration(variables) => {
                for declarator in &variables.declarations {
                    if let BindingPattern::BindingIdentifier(id) = &declarator.id {
                        self.facts.exports.push(id.name.as_str().to_string());
                    }
                }
            }
            _ => {}
        }
        walk::walk_export_declaration(self, export);
    }

    fn visit_export_default_declaration(&mut self, export: &ExportDefaultDeclaration<'a>) {
        self.facts.exports.push("default".to_string());
        walk::walk_export_default_declaration(self, export);
    }

    fn visit_export_from_declaration(&mut self, export: &ExportFromDeclaration<'a>) {
        let source = export.source.value.as_str().to_string();
        for specifier in &export.specifiers {
            self.facts.exports.push(export_name(&specifier.exported));
        }
        self.facts.imports.push(ImportFact {
            kind: "export".to_string(),
            source,
            specifiers: export
                .specifiers
                .iter()
                .map(|specifier| export_name(&specifier.exported))
                .collect(),
        });
        walk::walk_export_from_declaration(self, export);
    }

    fn visit_export_named_declaration(&mut self, export: &ExportNamedDeclaration<'a>) {
        for specifier in &export.specifiers {
            self.facts.exports.push(export_name(&specifier.exported));
        }
        walk::walk_export_named_declaration(self, export);
    }

    fn visit_import_declaration(&mut self, import: &ImportDeclaration<'a>) {
        // Imports were recorded during seeding; do not double-count.
        walk::walk_import_declaration(self, import);
    }

    fn visit_new_expression(&mut self, new: &NewExpression<'a>) {
        if let Some(path) = self.canonical(&new.callee) {
            if path == "BrowserWindow" || path.ends_with(".BrowserWindow") {
                self.facts.electron.uses_electron = true;
                let mut window = WindowFacts::default();
                if let Some(Expression::ObjectExpression(object)) =
                    new.arguments.first().and_then(|arg| arg.as_expression())
                {
                    for (key, value) in object_entries(object) {
                        if key == "webPreferences" {
                            if let Expression::ObjectExpression(preferences) = value {
                                for (pref_key, pref_value) in object_entries(preferences.as_ref()) {
                                    match pref_key.as_str() {
                                        "contextIsolation" => {
                                            window.context_isolation = bool_value(pref_value);
                                        }
                                        "nodeIntegration" => {
                                            window.node_integration = bool_value(pref_value);
                                        }
                                        "preload" => {
                                            window.preload = string_value(pref_value);
                                        }
                                        "sandbox" => {
                                            window.sandbox = bool_value(pref_value);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                self.facts.electron.windows.push(window);
            }
        }
        walk::walk_new_expression(self, new);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        // Top-level declarators were seeded; nested ones register
        // here so aliases exist before their uses are walked.
        self.record_declarator(declarator);
        walk::walk_variable_declarator(self, declarator);
    }
}

fn bool_value(expression: &Expression) -> Option<bool> {
    match expression {
        Expression::BooleanLiteral(literal) => Some(literal.value),
        _ => None,
    }
}

fn export_name(name: &ModuleExportName) -> String {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name.as_str().to_string(),
        ModuleExportName::IdentifierReference(identifier) => identifier.name.as_str().to_string(),
        ModuleExportName::StringLiteral(literal) => literal.value.as_str().to_string(),
    }
}

fn object_entries<'a>(object: &'a ObjectExpression<'a>) -> Vec<(String, &'a Expression<'a>)> {
    let mut entries = Vec::new();
    for property in &object.properties {
        if let ObjectPropertyKind::ObjectProperty(property) = property {
            entries.push((property_key_name(&property.key), &property.value));
        }
    }
    entries
}

fn object_keys(expression: &Expression) -> Vec<String> {
    match expression {
        Expression::ObjectExpression(object) => object_entries(object)
            .into_iter()
            .map(|(key, _)| key)
            .collect(),
        _ => Vec::new(),
    }
}

fn property_key_name(key: &PropertyKey) -> String {
    match key {
        PropertyKey::StaticIdentifier(identifier) => identifier.name.as_str().to_string(),
        PropertyKey::PrivateIdentifier(identifier) => identifier.name.as_str().to_string(),
        PropertyKey::StringLiteral(literal) => literal.value.as_str().to_string(),
        PropertyKey::NumericLiteral(literal) => literal.value.to_string(),
        _ => String::new(),
    }
}

fn require_source(call: &CallExpression) -> Option<String> {
    if let Expression::Identifier(identifier) = &call.callee {
        if identifier.name.as_str() == "require" {
            return call
                .arguments
                .first()
                .and_then(|arg| arg.as_expression())
                .and_then(string_value);
        }
    }
    None
}

fn string_value(expression: &Expression) -> Option<String> {
    match expression {
        Expression::StringLiteral(literal) => Some(literal.value.as_str().to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN_JS: &str = r#"
const { app, BrowserWindow, ipcMain } = require('electron');
const { greet } = require('./lib/util.js');
function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: '/abs/preload.js',
      sandbox: true,
    },
  });
  win.loadFile('index.html');
}
ipcMain.handle('fixture:greet', async () => greet('x'));
ipcMain.on('fixture:ping', () => {});
app.whenReady().then(createWindow);
"#;

    const PRELOAD_JS: &str = r#"
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('fixtureApi', {
  greet: (name) => ipcRenderer.invoke('fixture:greet', name),
  ping: () => ipcRenderer.send('fixture:ping'),
});
"#;

    #[test]
    fn adversarial_non_literal_channel_is_not_a_fact() {
        let source = "const { ipcMain } = require('electron'); const c = process.env.CH; ipcMain.handle(c, () => {});";
        let facts = analyze_source(Path::new("a.js"), source);
        assert!(facts.electron.ipc_handle.is_empty());
        assert!(facts.electron.uses_electron);
    }

    #[test]
    fn adversarial_syntax_error_is_a_finding_not_a_panic() {
        let facts = analyze_source(Path::new("a.js"), "const = {broken");
        assert!(!facts.parse_errors.is_empty());
    }

    #[test]
    fn validation_electron_main_facts() {
        let facts = analyze_source(Path::new("main.js"), MAIN_JS);
        assert!(facts.parse_errors.is_empty(), "{:?}", facts.parse_errors);
        assert_eq!(facts.electron.ipc_handle, vec!["fixture:greet".to_string()]);
        assert_eq!(facts.electron.ipc_on, vec!["fixture:ping".to_string()]);
        assert_eq!(facts.electron.windows.len(), 1);
        let window = &facts.electron.windows[0];
        assert_eq!(window.context_isolation, Some(true));
        assert_eq!(window.node_integration, Some(false));
        assert_eq!(window.preload.as_deref(), Some("/abs/preload.js"));
        assert_eq!(window.sandbox, Some(true));
        assert!(
            facts
                .imports
                .iter()
                .any(|fact| fact.source == "./lib/util.js")
        );
    }

    #[test]
    fn validation_preload_bridge_facts() {
        let facts = analyze_source(Path::new("preload.js"), PRELOAD_JS);
        assert!(facts.parse_errors.is_empty(), "{:?}", facts.parse_errors);
        assert_eq!(facts.electron.bridge_exposures.len(), 1);
        assert_eq!(facts.electron.bridge_exposures[0].name, "fixtureApi");
        assert_eq!(
            facts.electron.bridge_exposures[0].keys,
            vec!["greet".to_string(), "ping".to_string()]
        );
        assert_eq!(facts.electron.ipc_invoke, vec!["fixture:greet".to_string()]);
        assert_eq!(facts.electron.ipc_send, vec!["fixture:ping".to_string()]);
    }
}
