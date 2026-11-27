//! The MCP proxy, its rules and the ATR rule set: one test binary of what were 22, each file
//! a module as it stood. A change to the engine rebuilds and links one
//! binary here instead of one per file (the mutation runs rebuild the tests
//! for every mutant). Files that set the process's environment or its folder,
//! or measure time or memory, stay binaries of their own in `tests/`.

mod atr_refusal_names_what_matched;
mod atr_ssrf_dotlocal_path;
mod atr_test_cases;
mod atr_upstream_batch2;
mod atr_upstream_imports;
mod mcp_arg_chaining;
mod mcp_block_e2e;
mod mcp_description_poison_e2e;
mod mcp_effect_and_provenance;
mod mcp_pinning_follow_ups;
mod mcp_pinning_listed_marker_and_request_cursor;
mod mcp_pinning_paging_and_new_tool;
mod mcp_proxy_caps;
mod mcp_proxy_refusals;
mod mcp_remote_servers_e2e;
mod mcp_server_content_e2e;
mod mcp_server_gets_its_stop_request;
mod mcp_shell_call_shapes;
mod mcp_tool_pinning_e2e;
mod owasp_asi;
mod rule_compile_fails_closed;
mod rules_folder_foreign_yaml;
