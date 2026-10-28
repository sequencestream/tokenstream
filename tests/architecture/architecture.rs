use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, Item, ItemMod, ItemUse, UseTree};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Class {
    Assembly,
    DataPlane,
    ProxyAssembly,
    ProxyForwarding,
    ControlPlane,
    Events,
    Logging,
    Shared,
}

const REPOSITORY_CLASSES: &[(&str, Class)] = &[
    ("lib", Class::Assembly),
    ("main", Class::Assembly),
    ("admin", Class::ControlPlane),
    ("admin.assets", Class::ControlPlane),
    ("auth", Class::DataPlane),
    ("auth.gateway", Class::DataPlane),
    ("config", Class::Assembly),
    ("credentials", Class::ControlPlane),
    ("crypto", Class::Shared),
    ("crypto.aes_gcm", Class::Shared),
    ("crypto.gateway_secret", Class::Shared),
    ("crypto.password_work", Class::Shared),
    ("diagnostics", Class::Assembly),
    ("domain", Class::Shared),
    ("events", Class::Events),
    ("local_state", Class::Assembly),
    ("logging", Class::Logging),
    ("model_aliases", Class::ControlPlane),
    ("model_rewrite", Class::DataPlane),
    ("persistence", Class::Shared),
    ("persistence.postgres", Class::Shared),
    ("persistence.sqlite", Class::Shared),
    ("persistence.time", Class::Shared),
    ("providers", Class::ControlPlane),
    ("providers.health", Class::ControlPlane),
    ("proxy", Class::ProxyAssembly),
    ("proxy.admission", Class::ProxyForwarding),
    ("proxy.error", Class::ProxyAssembly),
    ("proxy.gateway", Class::ProxyAssembly),
    ("proxy.headers", Class::ProxyForwarding),
    ("proxy.http", Class::ProxyForwarding),
    ("proxy.layered", Class::ProxyForwarding),
    ("proxy.transport", Class::ProxyForwarding),
    ("proxy.websocket", Class::ProxyForwarding),
    ("routing", Class::DataPlane),
    ("routing.target", Class::DataPlane),
    ("telemetry", Class::Shared),
];

#[derive(Clone)]
struct SourceModule {
    name: String,
    file: PathBuf,
    syntax: syn::File,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Violation {
    code: &'static str,
    source: String,
    target: String,
    rule: &'static str,
    location: String,
}

impl Violation {
    fn render(&self) -> String {
        format!(
            "{} {} -> {}: {} [{}]",
            self.code, self.source, self.target, self.rule, self.location
        )
    }
}

fn check_tree(root: &Path, classes: &[(&str, Class)]) -> Vec<String> {
    let source_root = root.join("src");
    let mut violations = BTreeSet::new();
    let mut modules = BTreeMap::new();
    let mut test_files = BTreeSet::new();
    for (entry, name) in [("lib.rs", "lib"), ("main.rs", "main")] {
        let file = source_root.join(entry);
        if file.exists() {
            discover_module(
                &source_root,
                &file,
                name.to_owned(),
                source_root.clone(),
                &mut modules,
                &mut test_files,
                &mut violations,
            );
        }
    }

    let mut assigned = BTreeMap::new();
    for (module, class) in classes {
        if assigned.insert((*module).to_owned(), *class).is_some() {
            violations.insert(Violation {
                code: "E_DUPLICATE_CLASS",
                source: (*module).to_owned(),
                target: "classification".to_owned(),
                rule: "a production module must have exactly one classification",
                location: "architecture rules".to_owned(),
            });
        }
    }
    for module in modules.keys() {
        if !assigned.contains_key(module) {
            violations.insert(Violation {
                code: "E_UNCLASSIFIED",
                source: module.clone(),
                target: "classification".to_owned(),
                rule: "every discovered production module must be classified",
                location: relative(root, &modules[module].file),
            });
        }
    }
    for module in assigned.keys() {
        if !modules.contains_key(module) {
            violations.insert(Violation {
                code: "E_STALE_CLASS",
                source: module.clone(),
                target: "module tree".to_owned(),
                rule: "every classification must name a discovered production module",
                location: "architecture rules".to_owned(),
            });
        }
    }
    for (module, class) in &assigned {
        let is_proxy_module = module == "proxy" || module.starts_with("proxy.");
        let has_proxy_role = matches!(class, Class::ProxyAssembly | Class::ProxyForwarding);
        if is_proxy_module != has_proxy_role {
            violations.insert(Violation {
                code: "E_PROXY_ROLE",
                source: module.clone(),
                target: "classification".to_owned(),
                rule: "proxy modules must use a closed proxy assembly or forwarding role",
                location: "architecture rules".to_owned(),
            });
        }
    }

    let discovered_files: BTreeSet<_> = modules
        .values()
        .map(|module| canonical(&module.file))
        .collect();
    let mut rust_files = Vec::new();
    collect_rust_files(&source_root, &mut rust_files);
    rust_files.sort();
    for file in rust_files {
        if !discovered_files.contains(&canonical(&file)) && !test_files.contains(&canonical(&file))
        {
            violations.insert(Violation {
                code: "E_ORPHAN_SOURCE",
                source: relative(root, &file),
                target: "module tree".to_owned(),
                rule: "production Rust sources must be reachable from a crate entry",
                location: relative(root, &file),
            });
        }
    }

    let names: BTreeSet<_> = modules.keys().cloned().collect();
    for module in modules.values() {
        analyze_module(root, module, &names, &assigned, &mut violations);
    }
    violations.into_iter().map(|item| item.render()).collect()
}

fn discover_module(
    root: &Path,
    file: &Path,
    name: String,
    child_dir: PathBuf,
    modules: &mut BTreeMap<String, SourceModule>,
    test_files: &mut BTreeSet<PathBuf>,
    violations: &mut BTreeSet<Violation>,
) {
    let Ok(text) = fs::read_to_string(file) else {
        violations.insert(Violation {
            code: "E_SOURCE_READ",
            source: name,
            target: "module tree".to_owned(),
            rule: "production source must be readable",
            location: relative(root.parent().unwrap_or(root), file),
        });
        return;
    };
    let Ok(syntax) = syn::parse_file(&text) else {
        violations.insert(Violation {
            code: "E_SOURCE_PARSE",
            source: name,
            target: "module tree".to_owned(),
            rule: "production source must parse as Rust",
            location: relative(root.parent().unwrap_or(root), file),
        });
        return;
    };
    if modules.contains_key(&name) {
        violations.insert(Violation {
            code: "E_DUPLICATE_MODULE",
            source: name,
            target: "module tree".to_owned(),
            rule: "a production module must be declared once",
            location: relative(root.parent().unwrap_or(root), file),
        });
        return;
    }
    modules.insert(
        name.clone(),
        SourceModule {
            name: name.clone(),
            file: file.to_path_buf(),
            syntax: syntax.clone(),
        },
    );
    discover_children(
        root,
        file,
        &name,
        &child_dir,
        &syntax.items,
        modules,
        test_files,
        violations,
    );
}

#[allow(clippy::too_many_arguments)]
fn discover_children(
    root: &Path,
    owner_file: &Path,
    owner: &str,
    child_dir: &Path,
    items: &[Item],
    modules: &mut BTreeMap<String, SourceModule>,
    test_files: &mut BTreeSet<PathBuf>,
    violations: &mut BTreeSet<Violation>,
) {
    for item in items {
        let Item::Mod(module) = item else { continue };
        if test_only(&module.attrs) {
            collect_external_test_module_files(child_dir, module, test_files);
            continue;
        }
        if module.attrs.iter().any(|attr| attr.path().is_ident("path")) {
            violations.insert(Violation {
                code: "E_PATH_ATTRIBUTE",
                source: owner.to_owned(),
                target: module.ident.to_string(),
                rule: "path attributes are forbidden in production module declarations",
                location: relative(root.parent().unwrap_or(root), owner_file),
            });
            continue;
        }
        let child_name = if owner == "lib" || owner == "main" {
            module.ident.to_string()
        } else {
            format!("{owner}.{}", module.ident)
        };
        let next_dir = child_dir.join(module.ident.to_string());
        if let Some((_, inline)) = &module.content {
            let synthetic = syn::File {
                shebang: None,
                attrs: Vec::new(),
                items: inline.clone(),
            };
            if modules
                .insert(
                    child_name.clone(),
                    SourceModule {
                        name: child_name.clone(),
                        file: owner_file.to_path_buf(),
                        syntax: synthetic,
                    },
                )
                .is_some()
            {
                violations.insert(Violation {
                    code: "E_DUPLICATE_MODULE",
                    source: child_name.clone(),
                    target: "module tree".to_owned(),
                    rule: "a production module must be declared once",
                    location: relative(root.parent().unwrap_or(root), owner_file),
                });
            }
            discover_children(
                root,
                owner_file,
                &child_name,
                &next_dir,
                inline,
                modules,
                test_files,
                violations,
            );
            continue;
        }
        let flat = child_dir.join(format!("{}.rs", module.ident));
        let nested = next_dir.join("mod.rs");
        let child_file = match (flat.exists(), nested.exists()) {
            (true, false) => flat,
            (false, true) => nested,
            _ => {
                violations.insert(Violation {
                    code: "E_MODULE_FILE",
                    source: owner.to_owned(),
                    target: child_name,
                    rule: "external modules must resolve to exactly one conventional source file",
                    location: relative(root.parent().unwrap_or(root), owner_file),
                });
                continue;
            }
        };
        discover_module(
            root,
            &child_file,
            child_name,
            next_dir,
            modules,
            test_files,
            violations,
        );
    }
}

fn collect_external_test_module_files(
    child_dir: &Path,
    module: &ItemMod,
    test_files: &mut BTreeSet<PathBuf>,
) {
    if module.attrs.iter().any(|attr| attr.path().is_ident("path")) {
        return;
    }
    let next_dir = child_dir.join(module.ident.to_string());
    if let Some((_, items)) = &module.content {
        collect_test_child_files(&next_dir, items, test_files);
        return;
    }
    let flat = child_dir.join(format!("{}.rs", module.ident));
    let nested = next_dir.join("mod.rs");
    let file = match (flat.exists(), nested.exists()) {
        (true, false) => flat,
        (false, true) => nested,
        _ => return,
    };
    test_files.insert(canonical(&file));
    let Ok(text) = fs::read_to_string(file) else {
        return;
    };
    let Ok(syntax) = syn::parse_file(&text) else {
        return;
    };
    collect_test_child_files(&next_dir, &syntax.items, test_files);
}

fn collect_test_child_files(child_dir: &Path, items: &[Item], test_files: &mut BTreeSet<PathBuf>) {
    for item in items {
        if let Item::Mod(module) = item {
            collect_external_test_module_files(child_dir, module, test_files);
        }
    }
}

fn analyze_module(
    root: &Path,
    module: &SourceModule,
    modules: &BTreeSet<String>,
    classes: &BTreeMap<String, Class>,
    violations: &mut BTreeSet<Violation>,
) {
    let location = relative(root, &module.file);
    let mut imports = BTreeMap::new();
    let mut external_imports = BTreeMap::new();
    for item in &module.syntax.items {
        if test_item(item) {
            continue;
        }
        if let Item::ExternCrate(item) = item {
            let root = item.ident.to_string();
            let local = item
                .rename
                .as_ref()
                .map_or_else(|| root.clone(), |(_, rename)| rename.to_string());
            if is_payload_parser(
                classes.get(&module.name),
                std::slice::from_ref(&root),
                &external_imports,
            ) {
                violations.insert(Violation {
                    code: "E_PAYLOAD_CRATE",
                    source: module.name.clone(),
                    target: root.clone(),
                    rule: "proxy forwarding modules must not introduce application payload parsing",
                    location: location.clone(),
                });
            }
            external_imports.insert(local, vec![root]);
        }
    }
    for item in &module.syntax.items {
        if test_item(item) {
            continue;
        }
        if let Item::Use(item_use) = item {
            inspect_use(
                module,
                item_use,
                modules,
                classes,
                &location,
                &mut imports,
                &mut external_imports,
                violations,
            );
        }
    }
    let mut collector = PathCollector {
        paths: Vec::new(),
        includes: Vec::new(),
        macro_internal_paths: Vec::new(),
    };
    for item in &module.syntax.items {
        if !test_item(item) {
            collector.visit_item(item);
        }
    }
    for include in collector.includes {
        violations.insert(Violation {
            code: "E_INCLUDE_MACRO",
            source: module.name.clone(),
            target: include,
            rule: "include macros are forbidden in production modules",
            location: location.clone(),
        });
    }
    for path in collector.macro_internal_paths {
        violations.insert(Violation {
            code: "E_MACRO_INTERNAL_PATH",
            source: module.name.clone(),
            target: path,
            rule: "macro definitions must not hide explicit internal dependency paths",
            location: location.clone(),
        });
    }
    for path in collector.paths {
        let segments: Vec<_> = path
            .segments
            .iter()
            .map(|part| part.ident.to_string())
            .collect();
        if segments.is_empty() {
            continue;
        }
        if is_payload_parser(classes.get(&module.name), &segments, &external_imports) {
            violations.insert(Violation {
                code: "E_PAYLOAD_CRATE",
                source: module.name.clone(),
                target: segments[0].clone(),
                rule: "proxy forwarding modules must not introduce application payload parsing",
                location: location.clone(),
            });
        }
        if let Some(target) = resolve_path(&module.name, &segments, modules, &imports) {
            if target != module.name {
                apply_rules(&module.name, &target, classes, &location, violations);
            }
        } else if suspicious_internal_path(&segments, modules) {
            violations.insert(Violation {
                code: "E_UNKNOWN_PATH",
                source: module.name.clone(),
                target: segments.join("::"),
                rule: "explicit internal paths must normalize to a classified module",
                location: location.clone(),
            });
        }
    }
}

fn suspicious_internal_path(segments: &[String], modules: &BTreeSet<String>) -> bool {
    let Some(first) = segments.first().map(String::as_str) else {
        return false;
    };
    // A one-segment path is a name in scope, even when that name matches a module.
    // Module paths carry a separator or an explicit root.
    if segments.len() < 2 {
        return matches!(first, "crate" | "self" | "super" | "tokenstream");
    }
    matches!(first, "crate" | "self" | "super" | "tokenstream")
        || modules
            .iter()
            .any(|module| module == first || module.starts_with(&format!("{first}.")))
}

#[allow(clippy::too_many_arguments)]
fn inspect_use(
    module: &SourceModule,
    item: &ItemUse,
    modules: &BTreeSet<String>,
    classes: &BTreeMap<String, Class>,
    location: &str,
    imports: &mut BTreeMap<String, String>,
    external_imports: &mut BTreeMap<String, Vec<String>>,
    violations: &mut BTreeSet<Violation>,
) {
    let mut leaves = Vec::new();
    flatten_use(&item.tree, Vec::new(), &mut leaves);
    for (segments, local, renamed, glob) in leaves {
        if is_payload_parser(classes.get(&module.name), &segments, external_imports) {
            violations.insert(Violation {
                code: "E_PAYLOAD_CRATE",
                source: module.name.clone(),
                target: segments.join("::"),
                rule: "proxy forwarding modules must not introduce application payload parsing",
                location: location.to_owned(),
            });
        }
        let Some(target) = resolve_explicit(&module.name, &segments, modules) else {
            if matches!(
                segments.first().map(String::as_str),
                Some("crate" | "self" | "super")
            ) {
                violations.insert(Violation {
                    code: "E_UNKNOWN_PATH",
                    source: module.name.clone(),
                    target: segments.join("::"),
                    rule: "internal imports must normalize to a classified module",
                    location: location.to_owned(),
                });
            }
            if let Some(local) = local.filter(|local| local != "_") {
                external_imports.insert(local, segments);
            }
            continue;
        };
        if glob {
            violations.insert(Violation {
                code: "E_INTERNAL_GLOB",
                source: module.name.clone(),
                target,
                rule: "production code must not glob-import an internal module",
                location: location.to_owned(),
            });
            continue;
        }
        let normalized = normalize_segments(&module.name, &segments);
        let imports_module_itself = normalized
            .as_ref()
            .is_some_and(|path| path.join(".") == target);
        if renamed && imports_module_itself {
            violations.insert(Violation {
                code: "E_MODULE_ALIAS",
                source: module.name.clone(),
                target,
                rule: "production code must not alias an internal module",
                location: location.to_owned(),
            });
            continue;
        }
        if target != module.name {
            apply_rules(&module.name, &target, classes, location, violations);
        }
        if let Some(local) = local.filter(|local| local != "_") {
            imports.insert(local, target);
        }
    }
}

fn flatten_use(
    tree: &UseTree,
    prefix: Vec<String>,
    output: &mut Vec<(Vec<String>, Option<String>, bool, bool)>,
) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            flatten_use(&path.tree, next, output);
        }
        UseTree::Name(name) => {
            let mut path = prefix;
            path.push(name.ident.to_string());
            output.push((path, Some(name.ident.to_string()), false, false));
        }
        UseTree::Rename(rename) => {
            let mut path = prefix;
            path.push(rename.ident.to_string());
            output.push((path, Some(rename.rename.to_string()), true, false));
        }
        UseTree::Glob(_) => output.push((prefix, None, false, true)),
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use(item, prefix.clone(), output);
            }
        }
    }
}

fn resolve_path(
    source: &str,
    segments: &[String],
    modules: &BTreeSet<String>,
    imports: &BTreeMap<String, String>,
) -> Option<String> {
    if matches!(
        segments[0].as_str(),
        "crate" | "self" | "super" | "tokenstream"
    ) {
        return resolve_explicit(source, segments, modules);
    }
    if let Some(target) = imports.get(&segments[0]) {
        return Some(target.clone());
    }
    if source != "lib" && source != "main" {
        let child = format!("{source}.{}", segments[0]);
        if modules.contains(&child) {
            return Some(child);
        }
    }
    let sibling = if source == "lib" || source == "main" {
        segments[0].clone()
    } else {
        format!(
            "{}.{}",
            source.rsplit_once('.').map_or(source, |(parent, _)| parent),
            segments[0]
        )
    };
    modules.contains(&sibling).then_some(sibling)
}

fn resolve_explicit(
    source: &str,
    segments: &[String],
    modules: &BTreeSet<String>,
) -> Option<String> {
    let normalized = normalize_segments(source, segments)?;
    for end in (1..=normalized.len()).rev() {
        let candidate = normalized[..end].join(".");
        if modules.contains(&candidate) {
            return Some(candidate);
        }
    }
    if matches!(
        segments.first().map(String::as_str),
        Some("crate" | "tokenstream")
    ) {
        (normalized.len() <= 2 && modules.contains("lib")).then(|| "lib".to_owned())
    } else if matches!(segments.first().map(String::as_str), Some("self" | "super")) {
        modules.contains(source).then(|| source.to_owned())
    } else {
        None
    }
}

fn normalize_segments(source: &str, segments: &[String]) -> Option<Vec<String>> {
    let first = segments.first()?.as_str();
    match first {
        "crate" | "tokenstream" => Some(segments[1..].to_vec()),
        "self" => {
            let mut path: Vec<_> = if source == "lib" || source == "main" {
                Vec::new()
            } else {
                source.split('.').map(str::to_owned).collect()
            };
            path.extend_from_slice(&segments[1..]);
            Some(path)
        }
        "super" => {
            let mut path: Vec<_> = source.split('.').map(str::to_owned).collect();
            let mut consumed = 0;
            while segments.get(consumed).is_some_and(|item| item == "super") {
                path.pop()?;
                consumed += 1;
            }
            path.extend_from_slice(&segments[consumed..]);
            Some(path)
        }
        _ => Some(segments.to_vec()),
    }
}

fn apply_rules(
    source: &str,
    target: &str,
    classes: &BTreeMap<String, Class>,
    location: &str,
    violations: &mut BTreeSet<Violation>,
) {
    let source_class = classes.get(source);
    let target_class = classes.get(target);
    let target_top = target.split('.').next().unwrap_or(target);
    let forbidden = if source_class == Some(&Class::ProxyForwarding)
        && matches!(
            target_top,
            "admin"
                | "model_aliases"
                | "credentials"
                | "providers"
                | "logging"
                | "persistence"
                | "local_state"
        ) {
        Some((
            "E_PROXY_BOUNDARY",
            "proxy forwarding modules may depend only on data-plane contracts and shared capabilities",
        ))
    } else if is_data_plane(source_class) && matches!(target_top, "admin" | "model_aliases") {
        Some((
            "E_PLANE_BOUNDARY",
            "data-plane modules must not depend on control-plane administration or model aliases",
        ))
    } else if source == "events"
        && matches!(target_top, "logging" | "persistence" | "admin" | "proxy")
    {
        Some((
            "E_EVENT_BOUNDARY",
            "the lifecycle event boundary must not depend on consumers, storage, administration, or proxy code",
        ))
    } else if source.starts_with("routing")
        && !(target_top == "domain" || target.starts_with("routing"))
    {
        Some((
            "E_ROUTING_BOUNDARY",
            "routing may depend only on domain values and its own modules",
        ))
    } else if source == "domain" {
        Some((
            "E_DOMAIN_BOUNDARY",
            "domain values must not depend on other repository modules",
        ))
    } else if source.starts_with("persistence")
        && matches!(target_top, "admin" | "proxy" | "logging")
    {
        Some((
            "E_PERSISTENCE_BOUNDARY",
            "persistence must not depend on administration, proxy, or request-log consumers",
        ))
    } else if source.starts_with("crypto")
        && !(target_top == "domain" || target.starts_with("crypto"))
    {
        Some((
            "E_SHARED_BOUNDARY",
            "cryptographic capabilities may depend only on domain values and their own modules",
        ))
    } else if source == "telemetry" && target_top != "domain" {
        Some((
            "E_SHARED_BOUNDARY",
            "bounded metrics may depend only on domain values",
        ))
    } else if source_class.is_none() || target_class.is_none() {
        Some((
            "E_UNCLASSIFIED_EDGE",
            "both sides of every internal dependency must be classified",
        ))
    } else {
        None
    };
    if let Some((code, rule)) = forbidden {
        violations.insert(Violation {
            code,
            source: source.to_owned(),
            target: target.to_owned(),
            rule,
            location: location.to_owned(),
        });
    }
}

fn is_data_plane(class: Option<&Class>) -> bool {
    matches!(
        class,
        Some(Class::DataPlane | Class::ProxyAssembly | Class::ProxyForwarding)
    )
}

fn is_payload_parser(
    class: Option<&Class>,
    segments: &[String],
    external_imports: &BTreeMap<String, Vec<String>>,
) -> bool {
    if class != Some(&Class::ProxyForwarding) {
        return false;
    }
    let expanded = external_imports
        .get(&segments[0])
        .map(|prefix| {
            let mut expanded = prefix.clone();
            expanded.extend_from_slice(&segments[1..]);
            expanded
        })
        .unwrap_or_else(|| segments.to_vec());
    expanded.first().is_some_and(|root| root == "serde_json")
        || (expanded.first().is_some_and(|root| root == "serde")
            && expanded.iter().skip(1).any(|segment| {
                matches!(
                    segment.as_str(),
                    "de" | "Deserialize" | "DeserializeOwned" | "Deserializer" | "Visitor"
                )
            }))
}

struct PathCollector {
    paths: Vec<syn::Path>,
    includes: Vec<String>,
    macro_internal_paths: Vec<String>,
}

impl<'ast> Visit<'ast> for PathCollector {
    fn visit_item_mod(&mut self, _node: &'ast ItemMod) {}

    fn visit_path(&mut self, node: &'ast syn::Path) {
        self.paths.push(node.clone());
        visit::visit_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("include") || node.path.is_ident("include_str") {
            self.includes.push(node.path.segments[0].ident.to_string());
        }
        visit::visit_macro(self, node);
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if node.mac.path.is_ident("macro_rules") {
            self.macro_internal_paths
                .extend(explicit_internal_macro_paths(node.mac.tokens.clone()));
        }
        visit::visit_item_macro(self, node);
    }
}

fn explicit_internal_macro_paths(tokens: TokenStream) -> Vec<String> {
    fn flatten(tokens: TokenStream, output: &mut Vec<String>) {
        for token in tokens {
            match token {
                TokenTree::Group(group) => flatten(group.stream(), output),
                TokenTree::Ident(ident) => output.push(ident.to_string()),
                TokenTree::Punct(punct) => output.push(punct.as_char().to_string()),
                TokenTree::Literal(_) => {}
            }
        }
    }

    let mut flat = Vec::new();
    flatten(tokens, &mut flat);
    let mut paths = BTreeSet::new();
    for index in 0..flat.len() {
        let root = if flat[index] == "$" && flat.get(index + 1).is_some_and(|item| item == "crate")
        {
            Some("$crate")
        } else if matches!(
            flat[index].as_str(),
            "crate" | "self" | "super" | "tokenstream"
        ) {
            Some(flat[index].as_str())
        } else {
            None
        };
        let Some(root) = root else { continue };
        let colon = index + usize::from(root == "$crate") + 1;
        if flat.get(colon).is_some_and(|item| item == ":")
            && flat.get(colon + 1).is_some_and(|item| item == ":")
        {
            paths.insert(format!("{root}::"));
        }
    }
    paths.into_iter().collect()
}

fn test_item(item: &Item) -> bool {
    match item {
        Item::Const(item) => test_only(&item.attrs),
        Item::Enum(item) => test_only(&item.attrs),
        Item::ExternCrate(item) => test_only(&item.attrs),
        Item::Fn(item) => test_only(&item.attrs),
        Item::ForeignMod(item) => test_only(&item.attrs),
        Item::Impl(item) => test_only(&item.attrs),
        Item::Macro(item) => test_only(&item.attrs),
        Item::Mod(item) => test_only(&item.attrs),
        Item::Static(item) => test_only(&item.attrs),
        Item::Struct(item) => test_only(&item.attrs),
        Item::Trait(item) => test_only(&item.attrs),
        Item::TraitAlias(item) => test_only(&item.attrs),
        Item::Type(item) => test_only(&item.attrs),
        Item::Union(item) => test_only(&item.attrs),
        Item::Use(item) => test_only(&item.attrs),
        _ => false,
    }
}

fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string() == "test")
    })
}

fn collect_rust_files(directory: &Path, output: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("temporary architecture fixture");
    for (name, contents) in files {
        let path = temp.path().join(name);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(path, contents).expect("write fixture");
    }
    temp
}

fn has_code(violations: &[String], code: &str) -> bool {
    violations.iter().any(|item| item.starts_with(code))
}

#[test]
#[ignore = "run through make arch-check"]
fn repository_boundaries_hold() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let violations = check_tree(root, REPOSITORY_CLASSES);
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
#[ignore = "run through make arch-check"]
fn legal_paths_and_edges_are_accepted() {
    let temp = fixture(&[
        (
            "src/lib.rs",
            "pub mod domain; pub mod auth; pub mod inline { pub struct Local; }",
        ),
        (
            "src/domain.rs",
            "pub struct Value; #[macro_export] macro_rules! domain_value { () => { 1 } }",
        ),
        (
            "src/auth.rs",
            "use crate::domain::{Value as DomainValue}; trait T { fn value() -> crate::domain::Value; } impl T for DomainValue { fn value() -> super::domain::Value { crate::domain::Value } } fn local() -> self::DomainValue { crate::domain_value!(); crate::domain::Value }",
        ),
    ]);
    let classes = [
        ("lib", Class::Assembly),
        ("domain", Class::Shared),
        ("auth", Class::DataPlane),
        ("inline", Class::Shared),
    ];
    assert!(check_tree(temp.path(), &classes).is_empty());
}

#[test]
#[ignore = "run through make arch-check"]
fn representative_forbidden_edges_are_rejected() {
    let temp = fixture(&[
        (
            "src/lib.rs",
            "pub mod admin; pub mod domain; pub mod events; pub mod logging; pub mod model_aliases; pub mod persistence; pub mod proxy;",
        ),
        ("src/admin.rs", "pub struct Api;"),
        ("src/domain.rs", "pub struct Value;"),
        (
            "src/events.rs",
            "use crate::{logging::Writer, persistence::Store}; pub struct Bus(Writer, Store);",
        ),
        ("src/logging.rs", "pub struct Writer;"),
        ("src/model_aliases.rs", "pub struct Alias;"),
        ("src/persistence.rs", "pub struct Store;"),
        ("src/proxy.rs", "pub mod http;"),
        (
            "src/proxy/http.rs",
            "use crate::{admin::Api, logging::Writer, model_aliases::Alias, persistence::Store}; pub struct Bad(Api, Writer, Alias, Store);",
        ),
    ]);
    let classes = [
        ("lib", Class::Assembly),
        ("admin", Class::ControlPlane),
        ("domain", Class::Shared),
        ("events", Class::Events),
        ("logging", Class::Logging),
        ("model_aliases", Class::ControlPlane),
        ("persistence", Class::Shared),
        ("proxy", Class::ProxyAssembly),
        ("proxy.http", Class::ProxyForwarding),
    ];
    let violations = check_tree(temp.path(), &classes);
    assert!(has_code(&violations, "E_PROXY_BOUNDARY"));
    assert!(has_code(&violations, "E_EVENT_BOUNDARY"));
}

#[test]
#[ignore = "run through make arch-check"]
fn imports_proxy_roles_and_payload_parsers_fail_closed() {
    let import = fixture(&[
        ("src/lib.rs", "pub mod admin; pub mod proxy;"),
        ("src/admin.rs", "pub trait Capability {}"),
        ("src/proxy.rs", "pub mod renamed;"),
        (
            "src/proxy/renamed.rs",
            "use crate::admin::Capability as _; pub struct Forwarder;",
        ),
    ]);
    let incorrectly_classified = [
        ("lib", Class::Assembly),
        ("admin", Class::ControlPlane),
        ("proxy", Class::ProxyAssembly),
        ("proxy.renamed", Class::DataPlane),
    ];
    let violations = check_tree(import.path(), &incorrectly_classified);
    assert!(has_code(&violations, "E_PROXY_ROLE"));
    assert!(has_code(&violations, "E_PLANE_BOUNDARY"));

    let classes = [
        ("lib", Class::Assembly),
        ("admin", Class::ControlPlane),
        ("proxy", Class::ProxyAssembly),
        ("proxy.renamed", Class::ProxyForwarding),
    ];
    assert!(has_code(
        &check_tree(import.path(), &classes),
        "E_PROXY_BOUNDARY"
    ));

    for source in [
        "use serde_json as wire; fn decode(bytes: &[u8]) { let _ = wire::from_slice::<()>(&bytes); }",
        "use serde::Deserialize as Decode; struct Payload;",
        "use serde as wire; fn decode<'de, D: wire::Deserializer<'de>>() {}",
        "extern crate serde_json as wire; fn decode(bytes: &[u8]) { let _ = wire::from_slice::<()>(&bytes); }",
    ] {
        let payload = fixture(&[
            ("src/lib.rs", "pub mod proxy;"),
            ("src/proxy.rs", "pub mod transport;"),
            ("src/proxy/transport.rs", source),
        ]);
        let payload_classes = [
            ("lib", Class::Assembly),
            ("proxy", Class::ProxyAssembly),
            ("proxy.transport", Class::ProxyForwarding),
        ];
        let violations = check_tree(payload.path(), &payload_classes);
        assert!(
            has_code(&violations, "E_PAYLOAD_CRATE"),
            "payload parser escaped detection: {source}: {violations:?}"
        );
    }

    let serializer = fixture(&[
        ("src/lib.rs", "pub mod proxy;"),
        ("src/proxy.rs", "pub mod error;"),
        (
            "src/proxy/error.rs",
            "use serde::Serialize; #[derive(Serialize)] struct Envelope; fn encode(value: &Envelope) { let _ = serde_json::to_vec(value); }",
        ),
    ]);
    let serializer_classes = [
        ("lib", Class::Assembly),
        ("proxy", Class::ProxyAssembly),
        ("proxy.error", Class::ProxyAssembly),
    ];
    assert!(check_tree(serializer.path(), &serializer_classes).is_empty());
}

#[test]
#[ignore = "run through make arch-check"]
fn nested_modules_and_test_only_sources_are_classified_correctly() {
    let external = fixture(&[
        (
            "src/lib.rs",
            "pub mod outer; #[cfg(test)] mod tests; #[cfg(unix)] mod unix;",
        ),
        (
            "src/outer.rs",
            "pub mod child; pub mod sibling; fn own() -> child::Value { child::Value }",
        ),
        ("src/outer/child.rs", "pub struct Value;"),
        ("src/outer/sibling.rs", "pub struct Other;"),
        ("src/tests.rs", "compile_error!(\"test-only source\");"),
        ("src/unix.rs", "pub struct Production;"),
    ]);
    let external_classes = [
        ("lib", Class::Assembly),
        ("outer", Class::Shared),
        ("outer.child", Class::Shared),
        ("outer.sibling", Class::Shared),
        ("unix", Class::Shared),
    ];
    assert!(check_tree(external.path(), &external_classes).is_empty());

    let inline = fixture(&[(
        "src/lib.rs",
        "pub mod outer { pub mod child { pub struct Value; } fn own() -> child::Value { child::Value } }",
    )]);
    let inline_classes = [
        ("lib", Class::Assembly),
        ("outer", Class::Shared),
        ("outer.child", Class::Shared),
    ];
    assert!(check_tree(inline.path(), &inline_classes).is_empty());

    let suspicious = fixture(&[
        ("src/lib.rs", "pub mod domain; pub mod consumer;"),
        ("src/domain.rs", "pub struct Value;"),
        ("src/consumer.rs", "type Hidden = domain::Value;"),
    ]);
    let suspicious_classes = [
        ("lib", Class::Assembly),
        ("domain", Class::Shared),
        ("consumer", Class::ControlPlane),
    ];
    assert!(has_code(
        &check_tree(suspicious.path(), &suspicious_classes),
        "E_UNKNOWN_PATH"
    ));

    let bindings = fixture(&[
        (
            "src/lib.rs",
            "pub mod auth; pub mod config; pub mod events; pub mod providers; pub mod consumer;",
        ),
        ("src/auth.rs", "pub struct Pool;"),
        ("src/config.rs", "pub struct Settings;"),
        ("src/events.rs", "pub struct Bus;"),
        ("src/providers.rs", "pub struct Catalog;"),
        (
            "src/consumer.rs",
            "fn work(events: &[()], config: u8, auth: ()) { let providers = [1]; let _ = (events.len(), config, auth, providers.len()); }",
        ),
    ]);
    let binding_classes = [
        ("lib", Class::Assembly),
        ("auth", Class::DataPlane),
        ("config", Class::Assembly),
        ("events", Class::Events),
        ("providers", Class::ControlPlane),
        ("consumer", Class::ControlPlane),
    ];
    assert!(
        check_tree(bindings.path(), &binding_classes).is_empty(),
        "local names that match modules must not be internal paths"
    );
}

#[test]
#[ignore = "run through make arch-check"]
fn macro_definitions_cannot_hide_internal_paths() {
    let temp = fixture(&[
        ("src/lib.rs", "pub mod admin; pub mod consumer;"),
        ("src/admin.rs", "pub struct Api;"),
        (
            "src/consumer.rs",
            "macro_rules! hidden { () => { crate::admin::Api } } pub(crate) use hidden;",
        ),
    ]);
    let classes = [
        ("lib", Class::Assembly),
        ("admin", Class::ControlPlane),
        ("consumer", Class::ControlPlane),
    ];
    assert!(has_code(
        &check_tree(temp.path(), &classes),
        "E_MACRO_INTERNAL_PATH"
    ));
}

#[test]
#[ignore = "run through make arch-check"]
fn fail_closed_source_shapes_are_rejected() {
    let cases = [
        ("pub mod extra;", "pub struct Extra;", "E_UNCLASSIFIED"),
        ("", "", "E_STALE_CLASS"),
    ];
    for (lib, extra, code) in cases {
        let temp = fixture(&[("src/lib.rs", lib), ("src/extra.rs", extra)]);
        let classes = if code == "E_STALE_CLASS" {
            vec![("lib", Class::Assembly), ("missing", Class::Shared)]
        } else {
            vec![("lib", Class::Assembly)]
        };
        assert!(has_code(&check_tree(temp.path(), &classes), code));
    }

    let temp = fixture(&[
        ("src/lib.rs", "pub mod domain; pub mod consumer;"),
        ("src/domain.rs", "pub struct Value;"),
        (
            "src/consumer.rs",
            "use crate::domain::*; use crate::domain as values; type Unknown = crate::missing::nested::Thing; include!(\"generated.rs\");",
        ),
        ("src/orphan.rs", "pub struct Orphan;"),
    ]);
    let classes = [
        ("lib", Class::Assembly),
        ("domain", Class::Shared),
        ("consumer", Class::ControlPlane),
        ("consumer", Class::ControlPlane),
    ];
    let violations = check_tree(temp.path(), &classes);
    for code in [
        "E_DUPLICATE_CLASS",
        "E_INTERNAL_GLOB",
        "E_MODULE_ALIAS",
        "E_INCLUDE_MACRO",
        "E_UNKNOWN_PATH",
        "E_ORPHAN_SOURCE",
    ] {
        assert!(
            has_code(&violations, code),
            "missing {code}: {violations:?}"
        );
    }

    let temp = fixture(&[
        ("src/lib.rs", "#[path = \"elsewhere.rs\"] pub mod moved;"),
        ("src/elsewhere.rs", "pub struct Moved;"),
    ]);
    assert!(has_code(
        &check_tree(temp.path(), &[("lib", Class::Assembly)]),
        "E_PATH_ATTRIBUTE"
    ));
}

#[test]
#[ignore = "run through make arch-check"]
fn diagnostics_are_deterministic_and_relative() {
    let first = fixture(&[
        ("src/lib.rs", "pub mod proxy; pub mod admin;"),
        ("src/proxy.rs", "pub mod http;"),
        (
            "src/proxy/http.rs",
            "use crate::admin::Api; pub struct Bad(Api);",
        ),
        ("src/admin.rs", "pub struct Api;"),
    ]);
    let second = fixture(&[
        ("src/admin.rs", "pub struct Api;"),
        (
            "src/proxy/http.rs",
            "use crate::admin::Api; pub struct Bad(Api);",
        ),
        ("src/proxy.rs", "pub mod http;"),
        ("src/lib.rs", "pub mod proxy; pub mod admin;"),
    ]);
    let classes = [
        ("lib", Class::Assembly),
        ("proxy", Class::ProxyAssembly),
        ("proxy.http", Class::ProxyForwarding),
        ("admin", Class::ControlPlane),
    ];
    let left = check_tree(first.path(), &classes);
    let right = check_tree(second.path(), &classes);
    assert_eq!(left, right);
    assert!(
        left.iter()
            .all(|message| !message.contains(first.path().to_string_lossy().as_ref()))
    );
}
