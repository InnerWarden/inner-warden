//! Text in inline code or in a shell's here-document is data only where
//! no step of the line runs it. Each test holds one way a line runs what
//! it looks like it only writes or prints; each line is refused on main
//! and must stay refused here.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

fn assert_refused(lines: &[&str]) {
    for line in lines {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT: let `shell_heredoc_data_blanked` blank an `echo`
/// whatever the other commands of the body and the line do
/// (`command_runs_nothing_written`), and the file it wrote is run,
/// marked as a program or installed as a hook unread.
#[test]
fn a_heredoc_that_runs_what_it_wrote_is_refused() {
    assert_refused(&[
        "bash <<'EOF'\necho 'mkfs.ext4 /dev/sda1' > run.sh\nsh ru''n.sh\nEOF",
        "bash <<'EOF'\necho 'rm -rf $dir/build' > run.sh\nsh ru''n.sh\nEOF",
        "bash <<'EOF'\necho 'mkfs.ext4 /dev/sda1' > run.sh\nsh *.sh\nEOF",
        "bash <<'EOF'\ncd .git/hooks\necho 'mkfs.ext4 /dev/sda1' > pre-commit\nchmod +x *\nEOF",
        "bash <<'EOF'\necho 'mkfs.ext4 /dev/sda1' > run.sh\nsource ./r*.sh\nEOF",
        "bash <<'EOF'\necho 'mkfs.ext4 /dev/sda1' > run.sh\nf=run.sh; . \"$f\"\nEOF",
        "bash <<'EOF'\necho 'mkfs.ext4 /dev/sda1' > run.sh\nEOF\nsh r?n.sh",
    ]);
}

/// FAILS ON REVERT: read `(?{ })` in a pattern only when the pattern
/// interpolates, or a `${ }`/`@{ }` block in a string only when it opens
/// with `[` or `\\`, and Perl code that runs a command from inside a
/// string or a pattern is blanked as text.
#[test]
fn perl_code_inside_a_string_or_a_pattern_is_refused() {
    assert_refused(&[
        "perl <<'EOF'\n\"a\" =~ m'(?{ system q{rm -rf $dir/build} })';\nEOF",
        "perl <<'EOF'\n\"a\" =~ m'(?{ system q{mkfs.ext4 /dev/sda1} })';\nEOF",
        "perl <<'EOF'\nmy $x = \"@{ do { system q{rm -rf $dir/build} } }\";\nEOF",
        "perl <<'EOF'\nmy $x = \"${ system q{mkfs.ext4 /dev/sda1}; \\1 }\";\nEOF",
        "perl -e '$_ = q{a}; s'\\''(??{ system q{mkfs.ext4 /dev/sda1} })'\\''b'\\'';'",
    ]);
}

/// FAILS ON REVERT: read a Ruby symbol literal (`%s`, `%i`) as data, or
/// drop `instance_method` and `bind` from the names that may run beyond
/// reading, and a method taken by name and called is blanked as text.
#[test]
fn a_ruby_method_taken_by_name_and_called_is_refused() {
    assert_refused(&[
        "ruby -e 'Object.instance_method(%s(system)).bind(self).call(%q{mkfs.ext4 /dev/sda1})'",
        "ruby -e 'Kernel.instance_method(%i[system][0]).bind(self).call(%q{rm -rf $dir/build})'",
        "ruby -e 'Object.instance_method(%q(system)).bind_call(self, %q{mkfs.ext4 /dev/sda1})'",
    ]);
}

/// FAILS ON REVERT: take `line_may_run_a_written_file` out and what the
/// code writes to a file is blanked as text while the next step of the
/// line runs that file.
#[test]
fn a_file_inline_code_writes_and_the_line_runs_is_refused() {
    assert_refused(&[
        "perl -e 'open(my $f, \">\", \"x.sh\"); print $f q{mkfs.ext4 /dev/sda1}' && sh x.sh",
        "lua -e 'local f=io.open(\"x.sh\",\"w\") f:write(\"mkfs.ext4 /dev/sda1\") f:close()' && sh x.sh",
        "ruby -e 'File.write(\"x.sh\", %q{mkfs.ext4 /dev/sda1})' && sh x.sh",
        "ruby -e 'File.write(\"x.sh\", %q{mkfs.ext4 /dev/sda1})'; chmod +x x.sh; ./x.sh",
        "perl -e 'print q{mkfs.ext4 /dev/sda1}' > x.sh; bash x.sh",
    ]);
}
