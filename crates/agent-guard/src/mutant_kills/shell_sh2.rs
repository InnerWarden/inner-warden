//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `shell.rs` (run 42450235934, 2026-11-08).

use super::*;

fn owned_words(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

fn parse_bash_for_test(source: &str) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("the Bash grammar must load");
    parser
        .parse(source, None)
        .expect("tree-sitter must return a tree for any input")
}

/// Counts every node the way the projection budget walks a tree: named and
/// anonymous nodes alike, each exactly once.
fn count_tree_nodes(root: tree_sitter::Node<'_>) -> usize {
    let mut stack = vec![root];
    let mut count = 0usize;
    while let Some(node) = stack.pop() {
        count += 1;
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                stack.push(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    count
}

/// The shallowest level, counting the root as level 0, at which a node of
/// `kind` appears, with no depth limit of its own.
fn shallowest_level_of_kind(root: tree_sitter::Node<'_>, kind: &str) -> Option<usize> {
    let mut stack = vec![(root, 0usize)];
    let mut shallowest: Option<usize> = None;
    while let Some((node, level)) = stack.pop() {
        if node.kind() == kind {
            shallowest = Some(shallowest.map_or(level, |current| current.min(level)));
        }
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                stack.push((cursor.node(), level + 1));
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    shallowest
}

/// `echo $x` wrapped in `levels` nested subshells.
fn expansion_in_nested_subshells(levels: usize) -> String {
    format!("{}echo $x{}", "( ".repeat(levels), " )".repeat(levels))
}

/// A single command `x` followed by `arguments` bare words.
fn command_with_bare_arguments(arguments: usize) -> String {
    format!("x{}", " a".repeat(arguments))
}

/// `perl --` ends perl's own options: the next word is the program, and `-`
/// in that place means the program arrives on stdin. Without `--`, a bare
/// word is the script and `-c` is a syntax check that runs nothing. Inverting
/// the `--` test turns the very first word of every invocation into "the
/// option terminator", so the script name, the stdin marker and `-c` are all
/// misread, and a `curl ... | perl -- -` pipe stops being seen as code on
/// stdin.
///
/// FAILS ON REVERT: replace == with != in perl_code_input.
#[test]
fn perl_double_dash_ends_options_and_names_the_program() {
    assert_eq!(
        perl_code_input(&owned_words(&["--", "script.pl"])),
        CodeInput::Argument("script.pl".to_owned()),
        "after `--` the next word is the perl program"
    );
    assert_eq!(
        perl_code_input(&owned_words(&["--", "-"])),
        CodeInput::Stdin,
        "`perl -- -` reads its program from stdin"
    );
    assert_eq!(
        perl_code_input(&owned_words(&["-c", "script.pl"])),
        CodeInput::None,
        "`perl -c` only checks syntax and must not be read as code input"
    );
    assert_eq!(
        perl_code_input(&owned_words(&["script.pl"])),
        CodeInput::Argument("script.pl".to_owned()),
        "a bare first word is the perl script, not an option terminator"
    );
}

/// An option that takes a value (`ruby -I lib`, `ruby -r json`, `lua -l mod`)
/// consumes the word after it, so the program is the word after that value.
/// Stepping the index by multiplication instead of addition lands on the
/// value itself and reports the library name as the program. The value
/// option is placed after another flag on purpose: at index 0 the mutant
/// multiplies zero and loops forever, which would show up as a timeout
/// rather than as this assertion.
///
/// FAILS ON REVERT: replace += with *= in language_code_input.
#[test]
fn value_options_skip_their_value_before_the_program() {
    assert_eq!(
        ruby_code_input(&owned_words(&["-w", "-I", "lib", "script.rb"])),
        CodeInput::Argument("script.rb".to_owned()),
        "`-I lib` is a load path; the program is script.rb, not lib"
    );
    assert_eq!(
        ruby_code_input(&owned_words(&["-w", "-r", "json", "-e", "puts 1"])),
        CodeInput::Argument("puts 1".to_owned()),
        "`-r json` is a library; the program is the `-e` code"
    );
    assert_eq!(
        lua_code_input(&owned_words(&["-W", "-l", "socket", "script.lua"])),
        CodeInput::Argument("script.lua".to_owned()),
        "`-l socket` is a module; the program is script.lua, not socket"
    );
}

/// The kind search carries its own recursion bound so a pathologically deep
/// tree can never drive it into unbounded recursion. Every tree the guard
/// builds today passes the projection budget first, so the bound is pinned
/// here directly on a tree deeper than it: the search must give up beyond the
/// bound and still find the same kind of node when it is shallow. Multiplying
/// the depth by one instead of adding one keeps it at zero for ever, so the
/// bound never trips.
///
/// FAILS ON REVERT: replace + with * in node_contains_kind.
#[test]
fn kind_search_gives_up_beyond_its_depth_bound() {
    let shallow = parse_bash_for_test(&expansion_in_nested_subshells(4));
    assert!(
        node_contains_kind(shallow.root_node(), "simple_expansion", 0),
        "a shallow expansion must be found"
    );

    let deep = parse_bash_for_test(&expansion_in_nested_subshells(100));
    let level = shallowest_level_of_kind(deep.root_node(), "simple_expansion")
        .expect("the deeply nested tree must still hold the expansion");
    assert!(
        level > MAX_AST_DEPTH + 1,
        "the expansion must sit beyond the search bound for this test to mean anything, \
         found at level {level}"
    );
    assert!(
        !node_contains_kind(deep.root_node(), "simple_expansion", 0),
        "the search went past its depth bound and found a node at level {level}"
    );
}

/// The node budget is inclusive: a tree of exactly `MAX_AST_NODES` nodes is
/// still projected structurally, and only one more node sends the command to
/// the conservative raw scan. Turning `>` into `>=` refuses a tree that is
/// within the budget, so a command at the limit silently loses its structural
/// projection and every caller of `structure_available` treats it as
/// unparsed.
///
/// FAILS ON REVERT: replace > with >= in ast_exceeds_projection_budget.
#[test]
fn a_tree_of_exactly_the_node_budget_is_still_projected() {
    let budget = max_ast_nodes();

    let base = count_tree_nodes(parse_bash_for_test(&command_with_bare_arguments(0)).root_node());
    let one_more =
        count_tree_nodes(parse_bash_for_test(&command_with_bare_arguments(1)).root_node());
    assert_eq!(
        one_more,
        base + 1,
        "each bare argument must add exactly one word node, or the boundary below is not exact"
    );

    let at_budget = command_with_bare_arguments(budget - base);
    let tree = parse_bash_for_test(&at_budget);
    assert!(
        !tree.root_node().has_error(),
        "the boundary command must parse cleanly"
    );
    assert_eq!(
        count_tree_nodes(tree.root_node()),
        budget,
        "the boundary command must hold exactly the node budget"
    );
    assert!(
        !ast_exceeds_projection_budget(tree.root_node()),
        "a tree of exactly {budget} nodes is within the budget, not over it"
    );
    assert!(
        project(&at_budget).parsed,
        "a command at the node budget must still get a structural projection"
    );
    assert!(
        structure_available(&at_budget),
        "a command at the node budget must still report its structure as available"
    );

    let over_budget = command_with_bare_arguments(budget - base + 1);
    assert!(
        !project(&over_budget).parsed,
        "one node over the budget must fall back to the raw scan"
    );
}

/// For git and gh only message, body and search options carry data, plus the
/// attached `-dVALUE` form. A bare `-d` is a flag (`git push -d` deletes a
/// remote branch, `gh pr merge -d` deletes the branch after merging), so it
/// must stay visible to the threat matcher. Letting a two-character `-d`
/// through the length check masks the flag itself.
///
/// FAILS ON REVERT: replace > with >= in option_data_arguments.
#[test]
fn a_bare_dash_d_flag_stays_visible_in_git_and_gh() {
    for command in ["git push origin -d main", "gh pr merge 42 -d"] {
        let projected = project(command);
        assert!(projected.parsed, "must parse: {command}");
        assert_eq!(
            projected.scan, command,
            "a bare -d is a flag, not data, and was masked out of the scan"
        );
    }
}

/// After an attached inline program (`'-eprint("ok")'`, `'--eval=...'`) the
/// next word is a fresh argument and must be examined; only a separate `-e`
/// value is skipped together with its flag. Inverting the advance test skips
/// the word after an attached program, so a following `-e '...'` literal is
/// never recognised as output and its text leaks into the scan as if it were
/// executed code.
///
/// FAILS ON REVERT: replace != with == in safe_inline_output_arguments.
#[test]
fn literal_after_an_attached_inline_program_is_still_masked() {
    for command in [
        r#"perl '-eprint("ok")' -e 'print "rm -rf --no-preserve-root /"'"#,
        r#"ruby '-eputs("ok")' -e 'puts "rm -rf --no-preserve-root /"'"#,
        r#"node '--eval=console.log("ok")' -e 'console.log("rm -rf --no-preserve-root /")'"#,
    ] {
        let projected = project(command);
        assert!(projected.parsed, "must parse: {command}");
        assert!(
            !projected.scan.contains("\"ok\""),
            "the attached inline literal was not masked: {}",
            projected.scan
        );
        assert!(
            !projected.scan.contains("rm -rf --no-preserve-root /"),
            "the literal after an attached inline program was skipped and leaked: {}",
            projected.scan
        );
    }
}
