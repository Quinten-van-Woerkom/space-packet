//! Checks that the requirements traceability matrix in `TRACEABILITY.md` is complete and agrees
//! with the `Requirements:` annotations on the tests and Kani proofs in `src/lib.rs`.

use std::collections::{BTreeMap, BTreeSet};

/// Traceability matrix, mapping CCSDS 133.0-B-2 clauses to the items that verify them.
const MATRIX: &str = include_str!("../TRACEABILITY.md");

/// Source containing the annotated unit tests and Kani proofs.
const SOURCE: &str = include_str!("../src/lib.rs");

/// Normative clauses of CCSDS 133.0-B-2. Sections that are out of scope as a whole are listed
/// once, by their section number. Each must appear exactly once in the matrix.
const CLAUSES: &[&str] = &[
    "1.6.3",
    "3.2.2.1",
    "3.2.2.2",
    "3.2.3",
    "3.3",
    "3.4",
    "4.1.2.1",
    "4.1.2.2",
    "4.1.3.1",
    "4.1.3.2.1",
    "4.1.3.2.2",
    "4.1.3.3.1.1",
    "4.1.3.3.1.2",
    "4.1.3.3.2.1",
    "4.1.3.3.2.2",
    "4.1.3.3.2.3",
    "4.1.3.3.3.1",
    "4.1.3.3.3.2",
    "4.1.3.3.3.3",
    "4.1.3.3.3.4",
    "4.1.3.3.4.1",
    "4.1.3.3.4.2",
    "4.1.3.3.4.3",
    "4.1.3.3.4.4",
    "4.1.3.4.1.1",
    "4.1.3.4.1.2",
    "4.1.3.4.2.1",
    "4.1.3.4.2.2",
    "4.1.3.4.2.3",
    "4.1.3.4.3.1",
    "4.1.3.4.3.2",
    "4.1.3.4.3.3",
    "4.1.3.4.3.4",
    "4.1.3.5.1",
    "4.1.3.5.2",
    "4.1.3.5.3",
    "4.1.4.1.1",
    "4.1.4.1.2",
    "4.1.4.2",
    "4.1.4.3",
    "4.2",
    "4.3",
    "5.2",
    "A2",
];

/// An annotated verification item in the source.
struct Item {
    clauses: BTreeSet<String>,
    is_kani_proof: bool,
}

/// A row of the traceability matrix.
enum Row {
    /// Verified by the listed items, each flagged with whether it is marked as a Kani proof.
    Tested(Vec<(String, bool)>),
    OutOfScope,
}

/// Collects every function annotated with a `/// Requirements:` line, keyed by name.
fn annotated_items() -> BTreeMap<String, Item> {
    let mut items = BTreeMap::new();
    let mut pending: Option<(BTreeSet<String>, Vec<&str>)> = None;
    let mut in_attribute = false;
    for (index, line) in SOURCE.lines().enumerate() {
        let line = line.trim();
        if let Some(clauses) = line.strip_prefix("/// Requirements:") {
            let clauses = clauses.split(',').map(|clause| clause.trim().to_owned());
            pending = Some((clauses.collect(), Vec::new()));
        } else if let Some((clauses, attributes)) = pending.as_mut() {
            if in_attribute {
                // Continuation of an attribute that rustfmt spread over multiple lines.
                in_attribute = !line.ends_with(']');
            } else if line.starts_with("#[") {
                attributes.push(line);
                in_attribute = !line.ends_with(']');
            } else if let Some(signature) = line.strip_prefix("fn ") {
                let name = signature.split('(').next().unwrap().to_owned();
                let is_test = attributes.contains(&"#[test]");
                let is_kani_proof = attributes.contains(&"#[kani::proof]");
                assert!(
                    is_test || is_kani_proof,
                    "`{name}` is annotated with requirements, but is not a test or Kani proof"
                );
                let item = Item {
                    clauses: core::mem::take(clauses),
                    is_kani_proof,
                };
                assert!(
                    items.insert(name.clone(), item).is_none(),
                    "`{name}` is duplicated"
                );
                pending = None;
            } else {
                panic!(
                    "requirements annotation on line {} is not directly followed by a function",
                    index + 1
                );
            }
        }
    }
    items
}

/// Parses the rows of the traceability matrix, keyed by clause.
fn matrix_rows() -> BTreeMap<String, Row> {
    let mut rows = BTreeMap::new();
    for line in MATRIX.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let [_, clause, _, status, verified_by, _] = cells[..] else {
            continue;
        };
        if !clause.starts_with(|c: char| c.is_ascii_digit()) && !clause.starts_with('A') {
            continue;
        }
        assert!(
            !verified_by.is_empty(),
            "row {clause} has an empty last column"
        );
        let row = match status {
            "Tested" => Row::Tested(
                verified_by
                    .split(',')
                    .map(|entry| {
                        let entry = entry.trim();
                        let (name, marker) = entry
                            .strip_prefix('`')
                            .and_then(|entry| entry.split_once('`'))
                            .unwrap_or_else(|| panic!("row {clause}: malformed entry `{entry}`"));
                        (name.to_owned(), marker.trim() == "(Kani)")
                    })
                    .collect(),
            ),
            "Out of scope" => Row::OutOfScope,
            _ => panic!("row {clause} has unknown status `{status}`"),
        };
        assert!(
            rows.insert(clause.to_owned(), row).is_none(),
            "row {clause} is duplicated"
        );
    }
    rows
}

/// Every clause of the standard shall be in the matrix, every tested clause shall be traced to
/// existing tests or proofs that are annotated with it, and every annotation shall be in the
/// matrix.
#[test]
fn every_requirement_is_traced() {
    let items = annotated_items();
    let rows = matrix_rows();
    let mut errors = Vec::new();

    let expected: BTreeSet<&str> = CLAUSES.iter().copied().collect();
    let listed: BTreeSet<&str> = rows.keys().map(String::as_str).collect();
    for clause in expected.difference(&listed) {
        errors.push(format!("clause {clause} is missing from the matrix"));
    }
    for clause in listed.difference(&expected) {
        errors.push(format!("matrix row {clause} is not a known clause"));
    }

    for (clause, row) in &rows {
        let Row::Tested(entries) = row else {
            continue;
        };
        for (name, marked_kani) in entries {
            match items.get(name) {
                None => errors.push(format!(
                    "clause {clause}: `{name}` is not an annotated test or proof"
                )),
                Some(item) => {
                    if !item.clauses.contains(clause) {
                        errors.push(format!(
                            "clause {clause}: `{name}` is not annotated with this clause"
                        ));
                    }
                    if item.is_kani_proof != *marked_kani {
                        errors.push(format!(
                            "clause {clause}: `{name}` is marked incorrectly as (not) a Kani proof"
                        ));
                    }
                }
            }
        }
    }

    for (name, item) in &items {
        for clause in &item.clauses {
            match rows.get(clause) {
                Some(Row::Tested(entries)) if entries.iter().any(|(entry, _)| entry == name) => {}
                Some(Row::Tested(_)) => errors.push(format!(
                    "`{name}` verifies clause {clause}, but is not listed for it in the matrix"
                )),
                Some(Row::OutOfScope) => errors.push(format!(
                    "`{name}` verifies clause {clause}, which the matrix lists as out of scope"
                )),
                None => errors.push(format!(
                    "`{name}` verifies clause {clause}, which is not in the matrix"
                )),
            }
        }
    }

    assert!(
        errors.is_empty(),
        "traceability errors:\n{}",
        errors.join("\n")
    );
}
