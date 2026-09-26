package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type WASMInspector struct {
	mu          sync.RWMutex
	devMode     bool
	moduleDir   string
	maxMemPages int

	runtime    wazero.Runtime
	modules    map[string]api.Module
	inspectors map[string]*wasmInspectorDef
	ctx        context.Context
	ctxCancel  context.CancelFunc
}

type wasmInspectorDef struct {
	name   string
	path   string
	module api.Module
}

func NewWASMInspector(devMode bool, moduleDir string, maxMemPages int, modules []string) *WASMInspector {
	ctx, cancel := context.WithCancel(context.Background())

	w := &WASMInspector{
		devMode:     devMode,
		moduleDir:   moduleDir,
		maxMemPages: maxMemPages,
		modules:     make(map[string]api.Module),
		inspectors:  make(map[string]*wasmInspectorDef),
		ctx:         ctx,
		ctxCancel:   cancel,
	}

	runtime := wazero.NewRuntime(ctx)
	w.runtime = runtime

	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)

	if moduleDir != "" {
		w.loadModules(moduleDir, modules)
	}

	return w
}

func (w *WASMInspector) Name() string { return "wasm" }

func (w *WASMInspector) Inspect(ctx *RequestContext) (*Decision, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.inspectors) == 0 {
		return nil, nil
	}

	reqJSON := fmt.Sprintf(`{"method":"%s","path":"%s","ip":"%s"}`,
		ctx.Method, ctx.Path, ctx.RealIP)

	for _, def := range w.inspectors {
		if def.module == nil {
			continue
		}
		dec, err := w.callInspector(def, reqJSON)
		if err != nil {
			if w.devMode {
				slog.Debug("wasm: inspector error", "name", def.name, "error", err)
			}
			continue
		}
		if dec != nil {
			return dec, nil
		}
	}

	return nil, nil
}

func (w *WASMInspector) callInspector(def *wasmInspectorDef, reqJSON string) (*Decision, error) {
	inspect := def.module.ExportedFunction("inspect")
	if inspect == nil {
		return nil, nil
	}

	res, err := inspect.Call(w.ctx)
	if err != nil {
		return nil, fmt.Errorf("inspect call failed: %w", err)
	}

	if len(res) == 0 || res[0] == 0 {
		return nil, nil
	}

	return &Decision{
		Action:   ActionBlock,
		RuleID:   fmt.Sprintf("WASM_%s", def.name),
		RuleName: fmt.Sprintf("WASM Inspector: %s", def.name),
		Severity: "high",
		Score:    70,
		Evidence: fmt.Sprintf("WASM inspector %q returned block decision", def.name),
	}, nil
}

func (w *WASMInspector) loadModules(dir string, modules []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if w.devMode {
			slog.Debug("wasm: could not read module directory", "dir", dir, "error", err)
		}
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".wasm" {
			continue
		}

		if len(modules) > 0 {
			found := false
			for _, m := range modules {
				if m == entry.Name() || m == entry.Name()[:len(entry.Name())-len(ext)] {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		path := filepath.Join(dir, entry.Name())
		w.loadModule(path)
	}
}

func (w *WASMInspector) loadModule(path string) {
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		slog.Warn("wasm: failed to read module", "path", path, "error", err)
		return
	}

	name := filepath.Base(path)
	name = name[:len(name)-len(filepath.Ext(name))]

	moduleConfig := wazero.NewModuleConfig().WithName(name)

	module, err := w.runtime.InstantiateWithConfig(w.ctx, wasmBytes, moduleConfig)
	if err != nil {
		slog.Warn("wasm: failed to instantiate module", "name", name, "error", err)
		return
	}

	w.mu.Lock()
	w.modules[name] = module
	w.inspectors[name] = &wasmInspectorDef{
		name:   name,
		path:   path,
		module: module,
	}
	w.mu.Unlock()

	slog.Info("wasm: module loaded", "name", name, "path", path)
}

func (w *WASMInspector) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for name, mod := range w.modules {
		mod.Close(w.ctx)
		delete(w.modules, name)
	}
	w.runtime.Close(w.ctx)
	w.ctxCancel()
}
