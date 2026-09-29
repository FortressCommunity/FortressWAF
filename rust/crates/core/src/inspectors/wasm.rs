//! WASM sandbox inspector.
//!
//! Port of `internal/engine/wasm.go`. Module loading, the `inspect` export
//! contract (a non-zero i64 result means block), and the resulting decision are
//! preserved.
//!
//! ## Deviation (documented)
//!
//! Go embedded `wazero` to instantiate and call WASM modules. This port defines
//! the [`WasmRuntime`] trait so the crate does not hard-depend on a specific
//! WASM engine and the build stays lean. [`NoWasmRuntime`] is the default and
//! loads no modules (so inspection is a no-op), which matches the shipped
//! configuration where WASM is disabled. A production deployment wires in a
//! `wasmtime`/`wasmer`-backed implementation of the trait. See
//! `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

/// A loaded WASM inspector module.
pub trait WasmModule: Send + Sync {
    /// The module's export name (file stem).
    fn name(&self) -> &str;
    /// Call the module's `inspect` export. Returns the i64 result, or an error.
    fn call_inspect(&self) -> Result<i64, String>;
}

/// A runtime capable of loading modules from a directory and listing them.
pub trait WasmRuntime: Send + Sync {
    /// Load all `.wasm` modules under `dir`, optionally filtered by `modules`.
    fn load(&self, dir: &str, modules: &[String]) -> Vec<Arc<dyn WasmModule>>;
}

/// Default runtime: loads nothing (WASM disabled).
pub struct NoWasmRuntime;

impl WasmRuntime for NoWasmRuntime {
    fn load(&self, _dir: &str, _modules: &[String]) -> Vec<Arc<dyn WasmModule>> {
        Vec::new()
    }
}

struct InspectorDef {
    name: String,
    path: String,
    module: Arc<dyn WasmModule>,
}

pub struct WasmInspector {
    pub dev_mode: bool,
    module_dir: String,
    max_mem_pages: i32,
    inspectors: Arc<RwLock<HashMap<String, Arc<InspectorDef>>>>,
}

impl WasmInspector {
    /// Port of `NewWASMInspector`.
    pub fn new(
        dev_mode: bool,
        module_dir: String,
        max_mem_pages: i32,
        modules: Vec<String>,
        runtime: Arc<dyn WasmRuntime>,
    ) -> Self {
        let inspectors: Arc<RwLock<HashMap<String, Arc<InspectorDef>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        if !module_dir.is_empty() {
            let loaded = runtime.load(&module_dir, &modules);
            let mut map = inspectors.write();
            for module in loaded {
                let name = module.name().to_string();
                map.insert(
                    name.clone(),
                    Arc::new(InspectorDef {
                        name: name.clone(),
                        path: String::new(),
                        module,
                    }),
                );
                info!(name = name.as_str(), "wasm: module loaded");
            }
        }

        WasmInspector {
            dev_mode,
            module_dir,
            max_mem_pages,
            inspectors,
        }
    }

    /// Convenience constructor with the no-op runtime.
    pub fn disabled(dev_mode: bool) -> Self {
        Self::new(
            dev_mode,
            String::new(),
            0,
            Vec::new(),
            Arc::new(NoWasmRuntime),
        )
    }

    /// Port of `callInspector`.
    fn call_inspector(&self, def: &InspectorDef) -> Result<Option<Decision>, String> {
        let res = def.module.call_inspect()?;

        if res == 0 {
            return Ok(None);
        }

        Ok(Some(
            Decision::new(Action::Block, 70.0)
                .with_rule_id(format!("WASM_{}", def.name))
                .with_rule_name(format!("WASM Inspector: {}", def.name))
                .with_severity("high")
                .with_evidence(format!(
                    "WASM inspector {:?} returned block decision",
                    def.name
                )),
        ))
    }

    /// Accessor: configured module directory.
    pub fn module_dir(&self) -> &str {
        &self.module_dir
    }

    /// Accessor: configured max memory pages.
    pub fn max_mem_pages(&self) -> i32 {
        self.max_mem_pages
    }

    /// Number of loaded inspectors.
    pub fn loaded_count(&self) -> usize {
        self.inspectors.read().len()
    }
}

impl Inspector for WasmInspector {
    fn name(&self) -> &str {
        "wasm"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let inspectors: Vec<Arc<InspectorDef>> = {
            let map = self.inspectors.read();
            map.values().cloned().collect()
        };

        if inspectors.is_empty() {
            return Ok(None);
        }

        let _req_json = format!(
            r#"{{"method":"{}","path":"{}","ip":"{}"}}"#,
            ctx.method, ctx.path, ctx.real_ip
        );

        for def in inspectors {
            match self.call_inspector(&def) {
                Err(e) => {
                    if self.dev_mode {
                        debug!(
                            name = def.name.as_str(),
                            error = e.as_str(),
                            "wasm: inspector error"
                        );
                    }
                    continue;
                }
                Ok(None) => continue,
                Ok(Some(dec)) => return Ok(Some(dec)),
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    #[test]
    fn no_modules_is_noop() {
        let w = WasmInspector::disabled(false);
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        assert!(w.inspect(&mut ctx).unwrap().is_none());
    }

    fn block_runtime() -> Arc<dyn WasmRuntime> {
        struct M;
        struct R;
        impl WasmModule for M {
            fn name(&self) -> &str {
                "blocker"
            }
            fn call_inspect(&self) -> Result<i64, String> {
                Ok(1)
            }
        }
        impl WasmRuntime for R {
            fn load(&self, _dir: &str, _modules: &[String]) -> Vec<Arc<dyn WasmModule>> {
                vec![Arc::new(M)]
            }
        }
        Arc::new(R)
    }

    fn allow_runtime() -> Arc<dyn WasmRuntime> {
        struct M;
        struct R;
        impl WasmModule for M {
            fn name(&self) -> &str {
                "allower"
            }
            fn call_inspect(&self) -> Result<i64, String> {
                Ok(0)
            }
        }
        impl WasmRuntime for R {
            fn load(&self, _dir: &str, _modules: &[String]) -> Vec<Arc<dyn WasmModule>> {
                vec![Arc::new(M)]
            }
        }
        Arc::new(R)
    }

    #[test]
    fn blocking_module_blocks() {
        let w = WasmInspector::new(false, "/mods".into(), 0, vec![], block_runtime());
        assert_eq!(w.loaded_count(), 1);
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        let dec = w.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "WASM_blocker");
    }

    #[test]
    fn zero_result_allows() {
        let w = WasmInspector::new(false, "/mods".into(), 0, vec![], allow_runtime());
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        assert!(w.inspect(&mut ctx).unwrap().is_none());
    }
}
