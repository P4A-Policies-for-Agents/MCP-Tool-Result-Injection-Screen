// Copyright 2026 Salesforce, Inc. All rights reserved.
//! `ai-payloads` subset (inlined; lift into the shared crate later): the minimal
//! typed views this policy needs over MCP JSON-RPC Streamable-HTTP bodies and SSE
//! frames. Every parser is tolerant — unknown fields are ignored and a parse
//! failure surfaces as `None` so the policy can apply its `onOversize`/pass-through
//! behaviour rather than erroring.

use serde_json::Value;

/// What we learn from the REQUEST body (to thread to the response leg).
#[derive(Clone, Debug, Default)]
pub struct McpRequest {
    /// The JSON-RPC `method`, if this is a JSON-RPC envelope.
    pub method: Option<String>,
    /// `params.name` for a `tools/call`.
    pub tool_name: Option<String>,
}

/// Detect a JSON-RPC (MCP/A2A) envelope and, for `tools/call`, the tool name.
/// Handles a single object or the first call in a batch array.
pub fn parse_mcp_request(body: &[u8]) -> Option<McpRequest> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let obj = first_rpc(&v)?;
    let method = obj.get("method").and_then(Value::as_str).map(str::to_string);
    let tool_name = if method.as_deref() == Some("tools/call") {
        obj.pointer("/params/name").and_then(Value::as_str).map(str::to_string)
    } else {
        None
    };
    Some(McpRequest { method, tool_name })
}

/// First JSON-RPC message from a single object or a batch array.
fn first_rpc(v: &Value) -> Option<&Value> {
    match v {
        Value::Object(_) => Some(v),
        Value::Array(a) => a.iter().find(|e| e.is_object()),
        _ => None,
    }
}

/// A single MCP `tools/call` result we may screen and rewrite.
#[derive(Clone, Debug)]
pub struct ToolResult {
    /// JSON-RPC id of the enclosing response (preserved on rewrite).
    pub id: Value,
    /// Concatenated screenable text from `content[]` (+ structuredContent serialised).
    pub text: String,
    /// Whether the result already carried `isError: true` (we never screen those).
    pub is_error: bool,
    /// Whether there was any text at all (image/binary-only results are skippable).
    pub has_text: bool,
}

/// Join text parts with blank lines; binary/image parts become a placeholder so the
/// judge sees structure without the bytes. Optionally include embedded resource text.
pub fn text_of_content(content: &Value, include_resource_text: bool) -> (String, bool) {
    let mut parts: Vec<String> = Vec::new();
    let mut had_text = false;
    if let Some(arr) = content.as_array() {
        for item in arr {
            match item.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = item.get("text").and_then(Value::as_str) {
                        had_text = true;
                        parts.push(t.to_string());
                    }
                }
                Some("image") => parts.push("[image omitted]".to_string()),
                Some("resource") => {
                    if include_resource_text {
                        // Embedded resource: {resource:{text|blob, uri, mimeType}}
                        if let Some(t) = item.pointer("/resource/text").and_then(Value::as_str) {
                            had_text = true;
                            parts.push(t.to_string());
                        } else {
                            parts.push("[binary resource omitted]".to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (parts.join("\n\n"), had_text)
}

/// Extract the screenable view of a JSON-RPC `result` object (a `tools/call`
/// result). Returns `None` when the message is not a result we should screen
/// (it's an error, a notification, or has no id).
pub fn tool_result_view(msg: &Value, include_resource_text: bool) -> Option<ToolResult> {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    // A JSON-RPC error envelope — never screen.
    if msg.get("error").is_some() {
        return None;
    }
    let result = msg.get("result")?;
    let is_error = result.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let (mut text, has_text) = match result.get("content") {
        Some(c) => text_of_content(c, include_resource_text),
        None => (String::new(), false),
    };
    // Fold structuredContent in so injected instructions hidden in structured
    // fields are also seen by the judge.
    if let Some(sc) = result.get("structuredContent") {
        if !sc.is_null() {
            let serialised = serde_json::to_string(sc).unwrap_or_default();
            if !serialised.is_empty() && serialised != "null" {
                if !text.is_empty() {
                    text.push_str("\n\n");
                }
                text.push_str(&serialised);
            }
        }
    }
    Some(ToolResult { id, text, is_error, has_text })
}

/// Build the MCP "withheld" replacement result, preserving the JSON-RPC id. Uses
/// `isError: true` INSIDE `result` (not a JSON-RPC error) so the agent can see and
/// reason about the withholding, per MCP tool-execution-error convention.
pub fn withhold_result(id: &Value, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "isError": true,
            "content": [{ "type": "text", "text": message }]
        }
    })
}

/// Prepend a quarantine warning text item to a result's `content[]`, keeping the
/// original content. Returns whether it changed anything.
pub fn quarantine_in_place(result: &mut Value, warning: &str) -> bool {
    if let Some(arr) = result.get_mut("content").and_then(Value::as_array_mut) {
        arr.insert(0, serde_json::json!({ "type": "text", "text": warning }));
        true
    } else {
        false
    }
}

// ─── SSE (single-shot MCP tools/call responses) ─────────────────────────────

/// Extract the first complete JSON-RPC message from an SSE (`text/event-stream`)
/// body. MCP `tools/call` responses are single-shot (one `data:` event then close).
pub fn sse_first_json(text: &str) -> Option<Value> {
    let mut data_lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            if !data_lines.is_empty() {
                if let Ok(v) = serde_json::from_str::<Value>(&data_lines.join("\n")) {
                    return Some(v);
                }
                data_lines.clear();
            }
            continue;
        }
        if let Some(payload) = line.strip_prefix("data:") {
            data_lines.push(payload.strip_prefix(' ').unwrap_or(payload).to_string());
        }
    }
    if !data_lines.is_empty() {
        if let Ok(v) = serde_json::from_str::<Value>(&data_lines.join("\n")) {
            return Some(v);
        }
    }
    None
}

/// Re-wrap a single JSON-RPC message as one SSE `message` event.
pub fn wrap_sse(json_str: &str) -> String {
    format!("event: message\ndata: {json_str}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_tools_call_request() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_webpage","arguments":{"url":"x"}}}"#;
        let r = parse_mcp_request(body).unwrap();
        assert_eq!(r.method.as_deref(), Some("tools/call"));
        assert_eq!(r.tool_name.as_deref(), Some("fetch_webpage"));
    }

    #[test]
    fn non_tools_call_has_no_tool_name() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let r = parse_mcp_request(body).unwrap();
        assert_eq!(r.method.as_deref(), Some("tools/list"));
        assert!(r.tool_name.is_none());
    }

    #[test]
    fn extracts_text_and_structured_content() {
        let msg = json!({
            "jsonrpc":"2.0","id":7,
            "result":{"content":[{"type":"text","text":"hello"},{"type":"image","data":"..."}],
                       "structuredContent":{"note":"world"}}
        });
        let tr = tool_result_view(&msg, true).unwrap();
        assert_eq!(tr.id, json!(7));
        assert!(tr.has_text);
        assert!(tr.text.contains("hello"));
        assert!(tr.text.contains("world")); // structuredContent folded in
        assert!(!tr.is_error);
    }

    #[test]
    fn image_only_result_has_no_text() {
        let msg = json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":"x"}]}});
        let tr = tool_result_view(&msg, true).unwrap();
        assert!(!tr.has_text);
    }

    #[test]
    fn error_and_iserror_results_are_recognised() {
        let jsonrpc_err = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}});
        assert!(tool_result_view(&jsonrpc_err, true).is_none());
        let tool_err = json!({"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"nope"}]}});
        assert!(tool_result_view(&tool_err, true).unwrap().is_error);
    }

    #[test]
    fn withhold_preserves_id() {
        let w = withhold_result(&json!(42), "withheld");
        assert_eq!(w["id"], json!(42));
        assert_eq!(w["result"]["isError"], json!(true));
    }

    #[test]
    fn sse_roundtrip() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n";
        let v = sse_first_json(body).unwrap();
        assert_eq!(v["id"], json!(1));
        let rewrapped = wrap_sse(&v.to_string());
        assert!(rewrapped.starts_with("event: message\ndata: "));
    }
}
