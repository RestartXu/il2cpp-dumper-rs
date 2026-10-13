//! Ground-truth differential suite: recovered CIL vs the ORIGINAL managed IL.
//!
//! The full round trip is C# → managed IL (`Managed/*.dll`) → IL2CPP native →
//! recovered CIL (`Dump*/DummyDll/*.dll`). Both ends of that round trip are
//! real .NET assemblies, so we read them with `dotnetdll` and compare the
//! resolved method bodies directly — no IL2CPP toolchain is needed, because the
//! "before" side of the round trip ships with every corpus.
//!
//! The compiled native code is not a line-by-line image of the original IL
//! (register allocation, three-address lowering, inlining), so the comparison
//! cannot be a stack-opcode histogram. It is instead at the level of NAMED
//! REFERENCES — call targets, field accesses and string literals — which are
//! invariant across both compilations, plus coarse branch/return structure.
//!
//! Alignment is by `Type::Method(param count)`, walking `encloser` so nested
//! types get the same dotted name on both sides.
//!
//! `#[ignore]`d because it needs a dumped corpus on disk. Run it with:
//!
//! ```text
//! RT_MANAGED_DIR=../Cpp2IL/TestFiles/Simple_2019_4_34/Managed \
//! RT_RECOVERED_DIR=/tmp/rt/Dump0/DummyDll \
//!   cargo test --release --test roundtrip_difftest -- --ignored --nocapture
//! ```
//!
//! or through `scripts/diff_gate.sh`, which runs the dumper first.

use dotnetdll::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Named references a method makes, plus coarse structure. Deliberately free of
/// stack/local traffic (which differs between the original IL and the
/// three-address recovery) so a match means something.
#[derive(Default, Clone, PartialEq, Eq)]
struct MethodFp {
    calls: BTreeMap<String, u32>,
    fields: BTreeMap<String, u32>,
    strings: BTreeSet<String>,
    branches: u32,
    returns: u32,
    instructions: u32,
    /// The body carries one of the emitter's diagnostic strings — i.e. the
    /// recovery could not model something and substituted a note.
    has_diag: bool,
    /// Diagnostic references excluded from the maps above (see
    /// [`is_diag_marker`]), kept so the exclusion is auditable.
    diag_strings: u32,
    diag_calls: u32,
}

/// Markers `recovery::emit::diagnostic` writes into a body when it cannot
/// lower an operation. A body made ONLY of these (and no field access) is a
/// stub, not a recovery of the native code, and comparing it against the
/// original IL measures nothing.
///
/// The marker string and its `Console.WriteLine` sink are stripped from the
/// fingerprint BEFORE the maps are built ([`is_diag_marker`]), so a stub's
/// `calls` map is now empty and the `all(WriteLine)` test below holds
/// vacuously. It is kept as a guard for the `Pop` shape the emitter uses when
/// there is no sink method to call.
const DIAG_MARKERS: &[&str] = &[
    "not recovered",
    "could not be resolved",
    "missing from assembly",
    "call to unresolved address",
    "switch table",
    "conditional select",
    "leading zeros",
    "objective-c message send",
    "rotate (",
    "unmodelled",
];

impl MethodFp {
    fn is_diagnostic_stub(&self) -> bool {
        self.has_diag
            && self.fields.is_empty()
            && self
                .calls
                .keys()
                .all(|k| k.contains("WriteLine"))
    }
}

fn bump(m: &mut BTreeMap<String, u32>, k: String) {
    *m.entry(k).or_insert(0) += 1;
}

/// Canonicalize a rendered member reference down to its IDENTITY — the
/// declaring type and member name — so a `Definition` token (the original
/// assembly) and an external `Reference`/`MemberRef` (the recovered dummy
/// assembly) compare equal. The rendering differs in ways that are not
/// semantics: assembly scopes (`[mscorlib]`), generic argument lists (whose
/// parameter names differ, `T0` vs `M0`), `valuetype`/`class`, and the
/// signature itself (`ref T` on one side `object` on the other). The parameter
/// list is dropped deliberately: this suite asks whether the recovered method
/// still performs the same OPERATIONS, not whether it spelled the signature the
/// same way.
fn norm(shown: &str) -> String {
    fn strip(s: &str, open: char, close: char) -> String {
        let mut out = String::with_capacity(s.len());
        let mut depth = 0i32;
        for c in s.chars() {
            if c == open {
                depth += 1;
            } else if c == close {
                if depth > 0 {
                    depth -= 1;
                }
            } else if depth == 0 {
                out.push(c);
            }
        }
        out
    }
    let s = strip(shown, '[', ']');
    let s = strip(&s, '<', '>');
    let s = strip(&s, '(', ')');
    let s = s.replace('(', "").replace(')', "");
    let s = s.replace("valuetype ", "").replace("class ", " ");
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// True when `insn` is one of the emitter's own diagnostic notes.
///
/// `emit::Recoverer::diagnostic` lowers an unmodelled operation to
/// `ldstr "<marker>"` immediately followed by `call Console.WriteLine`. Both
/// halves are the RECOVERY's meta-information, not an operation the native code
/// performs, so neither belongs in the reference fingerprint: leaving them in
/// gave every method that recovered one diagnostic two spurious extra
/// references (`call:…Console.WriteLine` and the marker string) and made an
/// exact match impossible no matter how faithful the rest of the body was.
fn is_diag_marker(insn: &Instruction) -> bool {
    match insn {
        Instruction::LoadString(s) => {
            let v = String::from_utf16_lossy(s);
            DIAG_MARKERS.iter().any(|m| v.contains(m))
        }
        _ => false,
    }
}

fn fingerprint(res: &Resolution, insns: &[Instruction]) -> MethodFp {
    let mut fp = MethodFp::default();
    for (i, insn) in insns.iter().enumerate() {
        fp.instructions += 1;
        // The sink is identified POSITIONALLY — a call IMMEDIATELY preceded by
        // a marker string — not by the callee's name, so a genuine
        // `Console.WriteLine("hello")` is untouched.
        let diag_sink = i > 0 && is_diag_marker(&insns[i - 1]);
        match insn {
            // `#[flags(…)]` opcodes lower to struct variants carrying the flag
            // bits alongside `param0`.
            Instruction::Call { param0: s, .. }
            | Instruction::CallVirtual { param0: s, .. }
            | Instruction::CallVirtualTail(s)
            | Instruction::Jump(s) => {
                if diag_sink {
                    fp.diag_calls += 1;
                } else {
                    bump(&mut fp.calls, norm(&s.show(res)));
                }
            }
            Instruction::CallConstrained(_, s) | Instruction::CallVirtualConstrained(_, s) => {
                if diag_sink {
                    fp.diag_calls += 1;
                } else {
                    bump(&mut fp.calls, norm(&s.show(res)));
                }
            }
            Instruction::CallIndirect { .. } => bump(&mut fp.calls, "<calli>".into()),
            Instruction::NewObject(u) => bump(&mut fp.calls, norm(&u.show(res))),
            Instruction::LoadField { param0: f, .. }
            | Instruction::StoreField { param0: f, .. }
            | Instruction::LoadFieldAddress(f)
            | Instruction::LoadStaticField { param0: f, .. }
            | Instruction::StoreStaticField { param0: f, .. }
            | Instruction::LoadStaticFieldAddress(f)
            | Instruction::LoadFieldSkipNullCheck(f)
            | Instruction::StoreFieldSkipNullCheck(f)
            | Instruction::LoadTokenField(f) => bump(&mut fp.fields, norm(&f.show(res))),
            Instruction::LoadString(s) => {
                let v = String::from_utf16_lossy(s);
                if is_diag_marker(insn) {
                    fp.has_diag = true;
                    fp.diag_strings += 1;
                } else {
                    fp.strings.insert(v);
                }
            }
            Instruction::Branch(_)
            | Instruction::BranchEqual(_)
            | Instruction::BranchNotEqual(_)
            | Instruction::BranchLess(_, _)
            | Instruction::BranchGreater(_, _)
            | Instruction::BranchLessOrEqual(_, _)
            | Instruction::BranchGreaterOrEqual(_, _)
            | Instruction::BranchFalsy(_)
            | Instruction::BranchTruthy(_)
            | Instruction::Switch(_)
            | Instruction::Leave(_) => fp.branches += 1,
            Instruction::Return => fp.returns += 1,
            _ => {}
        }
    }
    fp
}

fn type_full_name(res: &Resolution, ti: TypeIndex) -> String {
    let td = &res[ti];
    let name = td.name.to_string();
    let qualified = match td.namespace.as_deref() {
        Some(ns) if !ns.is_empty() => format!("{ns}.{name}"),
        _ => name,
    };
    match td.encloser {
        Some(e) => format!("{}.{}", type_full_name(res, e), qualified),
        None => qualified,
    }
}

fn add_method(
    res: &Resolution,
    out: &mut HashMap<String, MethodFp>,
    ty: &str,
    m: &Method<'_>,
) {
    let Some(body) = &m.body else { return };
    if body.instructions.is_empty() {
        return;
    }
    let key = format!("{ty}::{}/{}", m.name, m.signature.parameters.len());
    // A property accessor is reachable both from `methods` and from the
    // property slot; keep the first, they are the same body.
    out.entry(key).or_insert_with(|| fingerprint(res, &body.instructions));
}

fn collect(res: &Resolution) -> HashMap<String, MethodFp> {
    let mut out = HashMap::new();
    for (ti, td) in res.enumerate_type_definitions() {
        let ty = type_full_name(res, ti);
        for m in &td.methods {
            add_method(res, &mut out, &ty, m);
        }
        for p in &td.properties {
            if let Some(g) = &p.getter {
                add_method(res, &mut out, &ty, g);
            }
            if let Some(s) = &p.setter {
                add_method(res, &mut out, &ty, s);
            }
        }
    }
    out
}

/// `(missing, extra)` name sets for a reference channel.
fn diff_keys(a: &BTreeMap<String, u32>, b: &BTreeMap<String, u32>) -> (Vec<String>, Vec<String>) {
    let missing = a.keys().filter(|k| !b.contains_key(*k)).cloned().collect();
    let extra = b.keys().filter(|k| !a.contains_key(*k)).cloned().collect();
    (missing, extra)
}

#[derive(Default)]
struct Totals {
    images_compared: usize,
    images_missing: Vec<String>,
    matched: usize,
    stubs: usize,
    exact: usize,
    missing_refs: usize,
    extra_refs: usize,
    methods_with_missing: usize,
    methods_with_extra: usize,
    branch_mismatch: usize,
    parse_failures: Vec<String>,
    /// Diagnostic references excluded from the comparison (see
    /// [`is_diag_marker`]) — reported so the exclusion stays auditable.
    diag_strings: usize,
    diag_calls: usize,
}

/// Parse one assembly and return its `Type::Method` → fingerprint map. Kept
/// self-contained so no borrowed `Resolution` escapes the byte buffer.
fn collect_file(path: &Path) -> Result<HashMap<String, MethodFp>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    match Resolution::parse(&data, ReadOptions::default()) {
        Ok(res) => Ok(collect(&res)),
        Err(e) => {
            // Distinguish a body problem from a table problem: if the same file
            // parses with bodies skipped, the defect is in an emitted body.
            let bodies = Resolution::parse(
                &data,
                ReadOptions { skip_method_bodies: true },
            );
            let hint = if bodies.is_ok() { " (tables ok, a BODY is malformed)" } else { "" };
            Err(format!("{e:?}{hint}"))
        }
    }
}

fn dlls_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "dll").unwrap_or(false))
        .collect();
    v.sort();
    v
}

#[test]
#[ignore = "needs a dumped corpus; run via scripts/diff_gate.sh"]
fn roundtrip_differential() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus = base.join("../Cpp2IL/TestFiles/Simple_2019_4_34");
    let managed_dir = std::env::var("RT_MANAGED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| corpus.join("Managed"));
    let recovered_dir = std::env::var("RT_RECOVERED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/rt/Dump0/DummyDll"));

    println!("managed   = {}", managed_dir.display());
    println!("recovered = {}", recovered_dir.display());

    let mut t = Totals::default();
    let mut worst: Vec<(usize, String, Vec<String>, Vec<String>)> = Vec::new();

    for managed in dlls_in(&managed_dir) {
        let name = managed.file_name().unwrap().to_string_lossy().to_string();
        let recovered = recovered_dir.join(&name);
        if !recovered.exists() {
            t.images_missing.push(name);
            continue;
        }
        let m = match collect_file(&managed) {
            Ok(m) => m,
            Err(e) => {
                t.parse_failures.push(format!("managed {name}: {e}"));
                continue;
            }
        };
        let r = match collect_file(&recovered) {
            Ok(r) => r,
            Err(e) => {
                t.parse_failures.push(format!("recovered {name}: {e}"));
                continue;
            }
        };
        t.images_compared += 1;

        for (key, mfp) in &m {
            let Some(rfp) = r.get(key) else { continue };
            if rfp.is_diagnostic_stub() {
                t.stubs += 1;
                continue;
            }
            t.diag_strings += rfp.diag_strings as usize;
            t.diag_calls += rfp.diag_calls as usize;
            t.matched += 1;
            let (mut miss, mut extra) = (Vec::new(), Vec::new());
            for (a, b, label) in [
                (&mfp.calls, &rfp.calls, "call"),
                (&mfp.fields, &rfp.fields, "field"),
            ] {
                let (mi, ex) = diff_keys(a, b);
                miss.extend(mi.into_iter().map(|k| format!("{label}:{k}")));
                extra.extend(ex.into_iter().map(|k| format!("{label}:{k}")));
            }
            for s in mfp.strings.difference(&rfp.strings) {
                miss.push(format!("str:{s:?}"));
            }
            for s in rfp.strings.difference(&mfp.strings) {
                extra.push(format!("str:{s:?}"));
            }
            let branch_mismatch = mfp.branches != rfp.branches;
            if miss.is_empty() && extra.is_empty() {
                t.exact += 1;
            } else {
                t.missing_refs += miss.len();
                t.extra_refs += extra.len();
                if !miss.is_empty() {
                    t.methods_with_missing += 1;
                }
                if !extra.is_empty() {
                    t.methods_with_extra += 1;
                }
                worst.push((miss.len() + extra.len(), format!("{name} {key}"), miss, extra));
            }
            if branch_mismatch {
                t.branch_mismatch += 1;
            }
        }
    }

    worst.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out = format!(
        "roundtrip differential\n  images compared: {}\n  images missing recovered: {}\n  \
         matched methods (comparable): {}\n  diagnostic stubs excluded: {}\n  \
         diagnostic refs excluded: {} strings + {} calls\n  \
         exact named-reference match: {} ({:.1}%)\n  \
         methods missing a reference: {}\n  methods with an extra reference: {}\n  \
         missing refs: {}\n  extra refs: {}\n  branch-count mismatches: {}\n  parse failures: {}\n",
        t.images_compared,
        t.images_missing.len(),
        t.matched,
        t.stubs,
        t.diag_strings,
        t.diag_calls,
        t.exact,
        if t.matched > 0 {
            100.0 * t.exact as f64 / t.matched as f64
        } else {
            0.0
        },
        t.methods_with_missing,
        t.methods_with_extra,
        t.missing_refs,
        t.extra_refs,
        t.branch_mismatch,
        t.parse_failures.len(),
    );
    out.push_str("\nworst methods (|missing|+|extra|):\n");
    for (n, what, miss, extra) in worst.iter().take(40) {
        out.push_str(&format!("  {n:3}  {what}\n"));
        if !miss.is_empty() {
            out.push_str(&format!("       missing: {}\n", miss.join(", ")));
        }
        if !extra.is_empty() {
            out.push_str(&format!("       extra:   {}\n", extra.join(", ")));
        }
    }
    if !t.images_missing.is_empty() {
        out.push_str(&format!("\nno recovered image for: {}\n", t.images_missing.join(", ")));
    }
    if !t.parse_failures.is_empty() {
        out.push_str(&format!("\nparse failures: {}\n", t.parse_failures.join(", ")));
    }
    println!("{out}");
    let _ = std::fs::write(base.join("target/roundtrip-report.txt"), &out);

    assert!(
        t.matched >= 50,
        "the differential did not align enough methods to be meaningful \
         ({} matched) — check RT_MANAGED_DIR / RT_RECOVERED_DIR",
        t.matched
    );
    if let Ok(min) = std::env::var("RT_MIN_EXACT_PCT") {
        let min: f64 = min.parse().expect("RT_MIN_EXACT_PCT must be a number");
        let pct = 100.0 * t.exact as f64 / t.matched.max(1) as f64;
        assert!(
            pct >= min,
            "exact named-reference match {pct:.2}% is below the floor {min:.2}%"
        );
    }
}
