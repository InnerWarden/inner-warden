# Sources of the external corpus

Each case in `cases.yml` carries a `source` field naming where it came from.
The measurements ran on 2026-11-20 against the guard built from `main` at
62ba3a1, on a throwaway machine, with an empty home per session. Nothing in
any source was executed against a real target: the poisoned model's shell
calls and the AgentDojo tool calls went to the guard and to a fake MCP server
that runs nothing.

| Source | What | Licence | In this repo |
|---|---|---|---|
| AgentDojo ([ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo), v0.1.35, commit a75aba7, benchmark suites v1.2.2) | the 35 injection tasks: the text its `important_instructions` attack places in a tool result, and the tool calls each task's ground truth makes; the tool calls of the 97 user tasks as benign controls | MIT, `LICENSES/agentdojo-MIT.txt` | yes, ids `xad-*` |
| model-poisoning-poc-example ([riyazwalikar/model-poisoning-poc-example](https://github.com/riyazwalikar/model-poisoning-poc-example), commit acb8e6c) | Qwen2.5-0.5B-Instruct fine-tuned with the project's own recipe, one model per payload, with the payload swapped for a line the guard must refuse; the shell calls each model emits on the project's three held-out prompt sets | MIT, `LICENSES/model-poisoning-poc-example-MIT.txt` | yes, ids `xmp-*` (the commands the models emitted; the prompts are not copied) |
| DVMCP, Damn Vulnerable MCP ([harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)) | 15 challenge servers, replayed through the proxy | the README says MIT and points to a LICENSE file the repository does not have | no: only the result, in `RESULTS.md` |

DVMCP is left out because the MIT terms ask for the copyright and permission
notice to travel with any copy, and upstream ships neither. Its result is
reported without its text.
