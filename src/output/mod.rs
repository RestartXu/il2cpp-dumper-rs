/// Print a styled informational note to stderr, matching the CLI's own output.
///
/// The library emits these while the CLI is drawing its banner (version
/// resolution, metadata-variant notes). An unstyled `Info: …` line in the
/// middle of that output reads like a stray debug print; the `ℹ` marker and dim
/// styling keep it visually part of the CLI's progress output.
pub fn note(msg: &str) {
    eprintln!(
        "  {} {}",
        console::style("ℹ").cyan().bold(),
        console::style(msg).dim()
    );
}

pub mod script_json;
pub mod decompiler;
pub mod pseudo_c;
pub mod struct_generator;
pub mod dummy_assembly_generator;
pub mod static_field_exporter;
pub mod header_constants;
pub mod embedded_scripts;
pub mod generics;
pub mod name_mangler;
pub mod cpp_scaffolding;

pub use script_json::*;
pub use decompiler::Il2CppDecompiler;
pub use struct_generator::StructGenerator;
pub use name_mangler::MangledNameBuilder;
pub use cpp_scaffolding::CppScaffolding;
pub mod cpp_type_dependency_graph;
pub mod cpp_ast;
pub mod cpp_type_model;

pub mod unity_version;
pub mod header_manager;
pub mod recovery_integration;
