//! Perl, PHP and Lua code that runs a shell line in ways the inline reader
//! did not follow.
//!
//! Measured 2026-11-20 on main b87c4f0 with `analyze_command`: Perl's
//! `open` with a pipe (`"|-"`, `"| sh"`), `"@{[ system(...) ]}"`, a call
//! through `&{"sys"."tem"}`, `readpipe`; PHP's `array_map("system", ...)`,
//! `("sys"."tem")(...)`, `include` of a path not read, of `php://input`, of
//! `expect://` or of a file the code writes, a file it writes and the line
//! then runs; Lua's `os.execute` through a local name, without brackets
//! (`os.execute"..."`, `os.execute[[...]]`), through `_G["os"]["execute"]`,
//! `rawget` or `pcall`: all allowed. The calls are entries of the reader's
//! tables of sinks and of calls through a value: a line the call runs is read
//! and judged, a call the reader cannot read is reviewed. Everyday Perl, PHP
//! and Lua lines stay allowed.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT: each was allowed on main; the line it runs is read.
#[test]
fn a_shell_line_perl_php_or_lua_runs_is_read_and_judged() {
    for line in [
        // perl-sym-call (main: allow)
        r#"perl -e '&{"sys"."tem"}("rm -rf ~/.ssh")'"#,
        // php-array-map (main: allow)
        r#"php -r 'array_map("system", ["rm -rf ~/.ssh"]);'"#,
        // php-concat-call (main: allow)
        r#"php -r '("sys"."tem")("rm -rf ~/.ssh");'"#,
        // php-fpc-sh (main: allow)
        r#"php -r 'file_put_contents("x.sh", "rm -rf ~/.ssh");' && sh x.sh"#,
        // lua-alias (main: allow)
        r#"lua -e 'local e = os.execute; e("rm -rf ~/.ssh")'"#,
        // lua-noparen (main: allow)
        r#"lua -e 'os.execute"rm -rf ~/.ssh"'"#,
        // lua-G (main: allow)
        r#"lua -e '_G["os"]["execute"]("rm -rf ~/.ssh")'"#,
        // lua-iopopen-noparen (main: allow)
        r#"lua -e 'io.popen"rm -rf ~/.ssh"'"#,
        // pl-readpipe (main: allow)
        r#"perl -e 'print readpipe("rm -rf ~/.ssh")'"#,
        // php-include-expect (main: allow)
        r#"php -r 'include "expect://rm -rf ~/.ssh";'"#,
        // php-fpc-include (main: allow)
        r#"php -r 'file_put_contents("x.php", "<?php system(\"rm -rf ~/.ssh\");"); include "x.php";'"#,
        // php-fpc-dot (main: allow)
        r#"php -r 'file_put_contents("x.sh", "rm -rf ~/.ssh");' && ./x.sh"#,
        // lua-holder (main: allow)
        r#"lua -e 'local o = os; o.execute("rm -rf ~/.ssh")'"#,
        // lua-pcall (main: allow)
        r#"lua -e 'pcall(os.execute, "rm -rf ~/.ssh")'"#,
        // lua-long (main: allow)
        r"lua -e 'os.execute[[rm -rf ~/.ssh]]'",
        // lua-rawget (main: allow)
        r#"lua -e 'rawget(_G, "os").execute("rm -rf ~/.ssh")'"#,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT: each was allowed on main; what the call runs is built at
/// run time or fed on its input, so it is held for review.
#[test]
fn a_call_the_reader_cannot_read_is_reviewed() {
    for line in [
        // perl-open-pipe (main: allow)
        r#"perl -e 'open(my $p, "|-", q{sh}); print $p "rm -rf ~/.ssh\n"'"#,
        // perl-open-pipe2 (main: allow)
        r#"perl -e 'open(P, "| sh"); print P "rm -rf ~/.ssh\n"'"#,
        // perl-open-pipe3 (main: allow)
        r#"perl -e 'open(P, "|sh") or die; print P "id"'"#,
        // perl-at-interp (main: allow)
        r#"perl -e 'print "@{[ system(q{rm -rf ~/.ssh}) ]}"'"#,
        // pl-amp-argv (main: allow)
        r#"perl -e '&{$ARGV[0]}("x")' a"#,
        // pl-open-var2 (main: allow)
        r"perl -e 'open(F, $ARGV[0]); print <F>' x",
        // php-var-argv (main: allow)
        r#"php -r '$f=$argv[1]; $f("ls");' x"#,
        // php-include-argv (main: allow)
        r"php -r 'include $argv[1];' x",
        // php-include-input (main: allow)
        r#"php -r 'include "php://input";'"#,
        // php-arraymap-argv (main: allow)
        r#"php -r 'array_map($argv[1], ["x"]);' a"#,
        // php-popen-sh (main: allow)
        r#"php -r '$p = popen("sh", "w"); fwrite($p, "rm -rf ~/.ssh");'"#,
        // php-fpc-var-sh (main: allow)
        r#"php -r 'file_put_contents("x.sh", $argv[1]);' x && bash x.sh"#,
        // lua-G-dyn (main: allow)
        r#"lua -e 'local k = arg[1]; _G[k].execute("x")' os"#,
        // lua-popen-w (main: allow)
        r#"lua -e 'io.popen("sh", "w"):write("rm -rf ~/.ssh")'"#,
        // lua-require-arg (main: allow)
        r"lua -e 'require(arg[1])' x",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
}

/// Everyday Perl, PHP and Lua lines stay allowed.
#[test]
fn everyday_perl_php_and_lua_stay_allowed() {
    for line in [
        r#"perl -e 'print "hello\n"'"#,
        r"perl -pi -e 's/foo/bar/g' src/main.rs",
        r"perl -ne 'print if /error/' app.log",
        r#"perl -e 'open(my $f, "<", "a.txt") or die; print while <$f>'"#,
        r#"perl -e 'open(P, "ls |"); print <P>'"#,
        r"php -r 'echo PHP_VERSION;'",
        r#"php -r 'echo json_encode(["a"=>1]);'"#,
        r#"php -r 'print_r(array_map("strtoupper", ["a","b"]));'"#,
        r#"php -r 'file_put_contents("out.txt", "hi");'"#,
        r#"php -r 'require "vendor/autoload.php"; echo 1;'"#,
        r"lua -e 'print(1+1)'",
        r"lua -e 'local t = {1,2}; print(#t)'",
        r#"lua -e 'os.execute("ls")'"#,
        r#"lua -e 'print(string.format("%d", 5))'"#,
        r"perl -e 'require JSON::PP; print 1'",
        r"perl -MJSON::PP -e 'print encode_json([1])'",
        r"perl -e 'do { print 1 } while 0'",
        r#"perl -e 'my @l = map { $_ * 2 } (1,2); print "@l"'"#,
        r#"perl -e 'print "sum: @{[ 1 + 2 ]}\n"'"#,
        r#"perl -e 'open(my $f, ">", "out.txt"); print $f "hi"'"#,
        r#"perl -e 'open(F, "<a.txt"); print <F>'"#,
        r"perl -e 'my %h = (a => 1); print $h{a}'",
        r"php -r '$a = [3,1]; usort($a, fn($x,$y) => $x <=> $y); print_r($a);'",
        r"php -r '$a=[1]; array_walk($a, function(&$v){ $v++; }); print_r($a);'",
        r#"php -r 'require __DIR__ . "/vendor/autoload.php";'"#,
        r"php -r '$f = function($x){ return $x; }; echo $f(1);'",
        r"php -r 'print_r(array_filter([1,0,2]));'",
        r"php -r 'print_r(array_map(fn($x) => $x * 2, [1,2]));'",
        r#"php -r '$x=1; echo "{$x}";'"#,
        r"php -r 'echo (1 + 2) * 3;'",
        r#"lua -e 'local s = string.rep("a", 3) print(s)'"#,
        r#"lua -e 'print(("x"):upper())'"#,
        r#"lua -e 'local t = {}; t["k"] = 1; print(t.k)'"#,
        r#"lua -e 'local ok = pcall(function() error("x") end) print(ok)'"#,
        r"lua -e 'print([[multi line]])'",
        r#"lua -e 'local s = require "string" print(s.len("a"))'"#,
        r#"lua -e 'print(os.date("%Y"))'"#,
        r#"lua -e 'print(os.getenv("USER"))'"#,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
