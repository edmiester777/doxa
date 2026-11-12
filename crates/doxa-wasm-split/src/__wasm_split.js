export function makeLoad(url, deps, fusedImports, initIt) {
  let alreadyLoaded = false;
  // Shared by concurrent callers: a second instance would re-run the part's data initializers.
  let loading = null;
  return async (callbackIndex, callbackData) => {
    await Promise.all(deps.map((dep) => dep()));
    if (alreadyLoaded) return;
    loading ??= instantiate().finally(() => {
      loading = null;
    });
    const mainExports = await loading;
    if (mainExports && callbackIndex !== undefined) {
      mainExports.__indirect_function_table.get(callbackIndex)(
        callbackData,
        true
      );
    }
  };

  async function instantiate() {
    try {
      const response = await fetch(url);
      const initSync = initIt || globalThis.__wasm_split_main_initSync;
      const mainExports = initSync(undefined, undefined);

      let imports = {
        env: {
          memory: mainExports.memory,
        },
        __wasm_split: {
          __indirect_function_table: mainExports.__indirect_function_table,
          __stack_pointer: mainExports.__stack_pointer,
          __tls_base: mainExports.__tls_base,
          memory: mainExports.memory,
        },
      };

      for (let mainExport in mainExports) {
        imports["__wasm_split"][mainExport] = mainExports[mainExport];
      }

      for (let name in fusedImports) {
        imports["__wasm_split"][name] = fusedImports[name];
      }

      let new_exports = await WebAssembly.instantiateStreaming(
        response,
        imports
      );

      alreadyLoaded = true;

      for (let name in new_exports.instance.exports) {
        fusedImports[name] = new_exports.instance.exports[name];
      }
      return mainExports;
    } catch (e) {
      console.error(
        "Failed to load wasm-split module",
        e,
        url,
        deps,
        fusedImports
      );
      return null;
    }
  }
}

let fusedImports = {};
