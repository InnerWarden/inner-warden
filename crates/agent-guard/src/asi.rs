//! OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10) taxonomy and mapping.
//!
//! The official framework was published by the OWASP GenAI Security Project on
//! 2025-12-09
//! (<https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>).
//! ASI = "Agentic Security Initiative".
//! This module carries the ten official risk classes and maps InnerWarden's
//! concrete detections (ATR rule categories + built-in command signals) to the
//! agentic risk they relate to, so a guard verdict can report *which* risk class
//! it touched (the "reason chain" on a deny).
//!
//! IMPORTANT, mapping honesty. A mapping here says "this detection is evidence
//! relevant to that ASI risk", NOT "InnerWarden fully covers that risk". Several
//! ASI classes (supply-chain provenance/SBOM, persistent-memory/RAG poisoning,
//! inter-agent message authentication) are NOT things a host-runtime guardrail
//! validates; where InnerWarden only mitigates the runtime *impact* it is scoped
//! as such on the public coverage page. An unmapped category returns `None`
//! rather than being force-fitted to a risk it does not actually evidence.
//!
//! InnerWarden is not endorsed or certified by OWASP; this is an independent
//! mapping to the published framework.

/// One OWASP Agentic Top 10 (2026) risk class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AsiThreat {
    pub id: &'static str,
    pub name: &'static str,
}

/// The ten official OWASP Top 10 for Agentic Applications 2026 risk classes, in
/// order. Titles are the published majority form; ASI05 is titled "Unexpected
/// Code Execution" (some sources add the "(RCE)" clarifier).
pub const ASI_TOP_10: [AsiThreat; 10] = [
    AsiThreat {
        id: "ASI01",
        name: "Agent Goal Hijack",
    },
    AsiThreat {
        id: "ASI02",
        name: "Tool Misuse & Exploitation",
    },
    AsiThreat {
        id: "ASI03",
        name: "Identity & Privilege Abuse",
    },
    AsiThreat {
        id: "ASI04",
        name: "Agentic Supply Chain Vulnerabilities",
    },
    AsiThreat {
        id: "ASI05",
        name: "Unexpected Code Execution",
    },
    AsiThreat {
        id: "ASI06",
        name: "Memory & Context Poisoning",
    },
    AsiThreat {
        id: "ASI07",
        name: "Insecure Inter-Agent Communication",
    },
    AsiThreat {
        id: "ASI08",
        name: "Cascading Failures",
    },
    AsiThreat {
        id: "ASI09",
        name: "Human-Agent Trust Exploitation",
    },
    AsiThreat {
        id: "ASI10",
        name: "Rogue Agents",
    },
];

/// Look up an [`AsiThreat`] by its id (`"ASI02"`), if valid.
pub fn threat(id: &str) -> Option<&'static AsiThreat> {
    ASI_TOP_10.iter().find(|t| t.id == id)
}

/// Map an ATR rule category to the primary OWASP Agentic (2026) risk id it
/// evidences. Unknown categories return `None` (honest: an unmapped category
/// claims no ASI).
pub fn category_to_asi(category: &str) -> Option<&'static str> {
    Some(match category.trim().to_ascii_lowercase().as_str() {
        // ASI01 Agent Goal Hijack, injected/manipulated intent steers the
        // agent's objective (incl. prompts that coax it into revealing context).
        "prompt-injection"
        | "agent-manipulation"
        | "cjk-social-engineering"
        | "consent-bypass-instruction"
        | "context-exfiltration" => "ASI01",
        // ASI02 Tool Misuse & Exploitation, a legitimate tool driven to an
        // unsafe/unauthorized call: a poisoned tool description or a compromised
        // skill exploited against the agent at runtime.
        "tool-poisoning" | "skill-compromise" => "ASI02",
        // ASI03 Identity & Privilege Abuse, inherited/cached credentials or
        // privilege escalated beyond what the agent should hold.
        "credential-exposure" | "privilege-escalation" => "ASI03",
        // ASI04 Agentic Supply Chain Vulnerabilities has NO detection mapping on
        // purpose: it is about component provenance (SBOM/signatures/registries),
        // which a host-runtime guardrail does not validate. InnerWarden only
        // mitigates the *impact* of a compromised component that tries to run a
        // payload (that shows up as ASI05), so no category is force-fitted here.
        // ASI06 Memory & Context Poisoning, false/malicious data implanted into
        // memory, RAG, or shared context to corrupt future reasoning.
        "data-poisoning" | "consensus-poisoning" => "ASI06",
        // ASI07 Insecure Inter-Agent Communication, spoofing/sybil across the
        // agent-to-agent channel.
        "agent-identity-spoofing" | "consensus-sybil-attack" => "ASI07",
        // ASI09 Human-Agent Trust Exploitation, over-trust / approval fatigue
        // used to get a human to wave a dangerous action through.
        "excessive-autonomy" | "approval-fatigue" => "ASI09",
        // ASI10 Rogue Agents, an agent operating outside its scope, incl.
        // covering its tracks to keep appearing legitimate.
        "audit-evasion" => "ASI10",
        // ASI08 Cascading Failures, one fault propagating across the system.
        "cascading-failure" => "ASI08",
        _ => return None,
    })
}

/// Map a built-in command signal label (from `analyze_command`) to the primary
/// OWASP Agentic (2026) risk id it evidences.
pub fn signal_to_asi(signal: &str) -> Option<&'static str> {
    Some(match signal {
        // ASI05 Unexpected Code Execution, running unvalidated/unauthorized
        // code: download-and-execute, temp-dir executables, obfuscated payloads,
        // reverse shells.
        "obfuscated_command"
        | "download_and_execute"
        | "download_chmod_execute"
        | "dynamic_code_execution"
        | "tmp_execution"
        // The aggravating factors that turn a fetch-and-execute from a shape into a
        // verdict evidence the same class as the shape they qualify.
        | "fetch_exec_no_tls"
        | "fetch_exec_ephemeral_host"
        | "fetch_exec_shortened_source"
        | "fetch_exec_decoder"
        | "reverse_shell" => "ASI05",
        // ASI02 Tool Misuse & Exploitation, the shell tool driven to a
        // dangerous call.
        "dangerous_command" => "ASI02",
        // ASI03 Identity & Privilege Abuse, loosening permissions on a system
        // path (the credential-read side is carried by the ATR
        // `credential-exposure` category, not a command signal).
        "insecure_permissions" | "sensitive_credential_read" | "protected_secret_read" => "ASI03",
        // ASI10 Rogue Agents, out-of-scope destructive/persistence behaviour
        // and tampering with the security layer to keep operating.
        "security_tooling_tamper" | "destructive_command" | "persistence_attempt" => "ASI10",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top10_is_complete_and_unique() {
        assert_eq!(ASI_TOP_10.len(), 10);
        for (i, t) in ASI_TOP_10.iter().enumerate() {
            assert_eq!(t.id, format!("ASI{:02}", i + 1));
            assert!(!t.name.is_empty());
        }
    }

    #[test]
    fn official_2026_titles_are_exact() {
        // Locks the official OWASP Top 10 for Agentic Applications 2026 titles
        // (published 2025-12-09) so the taxonomy cannot silently drift back to
        // the pre-publication names.
        let names: Vec<&str> = ASI_TOP_10.iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            vec![
                "Agent Goal Hijack",
                "Tool Misuse & Exploitation",
                "Identity & Privilege Abuse",
                "Agentic Supply Chain Vulnerabilities",
                "Unexpected Code Execution",
                "Memory & Context Poisoning",
                "Insecure Inter-Agent Communication",
                "Cascading Failures",
                "Human-Agent Trust Exploitation",
                "Rogue Agents",
            ]
        );
    }

    #[test]
    fn key_mappings_match_official_semantics() {
        // Anchor the corrected meanings so a signal can't drift back to the old
        // taxonomy (e.g. reverse_shell used to map to "Rogue Agents/ASI10" when
        // ASI05 was mislabelled "Privilege Escalation").
        assert_eq!(signal_to_asi("reverse_shell"), Some("ASI05"));
        assert_eq!(signal_to_asi("download_and_execute"), Some("ASI05"));
        assert_eq!(signal_to_asi("insecure_permissions"), Some("ASI03"));
        assert_eq!(category_to_asi("privilege-escalation"), Some("ASI03"));
        assert_eq!(category_to_asi("credential-exposure"), Some("ASI03"));
        assert_eq!(category_to_asi("data-poisoning"), Some("ASI06"));
        assert_eq!(category_to_asi("agent-identity-spoofing"), Some("ASI07"));
        assert_eq!(category_to_asi("cascading-failure"), Some("ASI08"));
        assert_eq!(category_to_asi("approval-fatigue"), Some("ASI09"));
        // A compromised skill is a tool exploited against the agent (ASI02), not
        // a supply-chain provenance finding (ASI04 has no detection mapping).
        assert_eq!(category_to_asi("skill-compromise"), Some("ASI02"));
        assert_eq!(category_to_asi("model-security"), None);
    }

    #[test]
    fn mappings_only_yield_valid_ids() {
        for c in [
            "prompt-injection",
            "tool-poisoning",
            "privilege-escalation",
            "skill-compromise",
            "data-poisoning",
            "agent-identity-spoofing",
            "approval-fatigue",
            "audit-evasion",
            "cascading-failure",
        ] {
            assert!(
                threat(category_to_asi(c).unwrap()).is_some(),
                "category {c}"
            );
        }
        for s in [
            "reverse_shell",
            "download_and_execute",
            "dangerous_command",
            "insecure_permissions",
            "security_tooling_tamper",
            "obfuscated_command",
        ] {
            assert!(threat(signal_to_asi(s).unwrap()).is_some(), "signal {s}");
        }
        assert!(category_to_asi("not-a-real-category").is_none());
        assert!(signal_to_asi("not_a_signal").is_none());
        // `credential_access` is a MITRE tactic label, not a command signal
        // `analyze_command` emits, so it has no ASI mapping here.
        assert!(signal_to_asi("credential_access").is_none());
    }
}
