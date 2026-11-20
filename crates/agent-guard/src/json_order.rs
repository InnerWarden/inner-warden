//! Writing an agent's JSON file back in the order the person wrote it.
//!
//! `serde_json::Value` keeps an object's keys sorted (the crate is built
//! without `preserve_order`, and turning that on changes the order of every
//! JSON this workspace writes, the dashboard's and the record's included). A
//! file of the agent's that `agents connect` rewrites (Cursor's
//! `~/.cursor/hooks.json`, Gemini's `~/.gemini/settings.json`, an MCP
//! config) is merged as a `Value`, and then written here in the order its
//! keys had in the file it was read from: only what the guard added or took
//! out moves.

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::Value;

/// A JSON value with every object's keys in the order they were read.
#[derive(Debug, Clone, PartialEq)]
enum Ordered {
    Leaf(Value),
    Array(Vec<Ordered>),
    Object(Vec<(String, Ordered)>),
}

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Read;
        impl<'de> Visitor<'de> for Read {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::String(v.to_string())))
            }
            fn visit_string<E>(self, v: String) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::String(v)))
            }
            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::Null))
            }
            fn visit_none<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Ordered, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Ordered::Array(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Ordered, A::Error> {
                let mut entries: Vec<(String, Ordered)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Ordered>()? {
                    // A key given twice: the last one counts, as for Value.
                    entries.retain(|(seen, _)| *seen != key);
                    entries.push((key, value));
                }
                Ok(Ordered::Object(entries))
            }
        }
        deserializer.deserialize_any(Read)
    }
}

impl Serialize for Ordered {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Leaf(value) => value.serialize(serializer),
            Self::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// PURE: `merged`, with each object's keys in the order the same object had
/// in `before`, and every key `before` did not have after those, in
/// `merged`'s order. The values are always `merged`'s; `before` lends
/// only the order. A list's items are matched by their place.
fn in_order_of(before: Option<&Ordered>, merged: &Value) -> Ordered {
    match merged {
        Value::Object(map) => {
            let mut entries = Vec::with_capacity(map.len());
            if let Some(Ordered::Object(old)) = before {
                for (key, old_value) in old {
                    if let Some(value) = map.get(key) {
                        entries.push((key.clone(), in_order_of(Some(old_value), value)));
                    }
                }
            }
            for (key, value) in map {
                if !entries.iter().any(|(seen, _)| seen == key) {
                    entries.push((key.clone(), in_order_of(None, value)));
                }
            }
            Ordered::Object(entries)
        }
        Value::Array(items) => {
            let old = match before {
                Some(Ordered::Array(old)) => old.as_slice(),
                _ => &[],
            };
            Ordered::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(at, value)| in_order_of(old.get(at), value))
                    .collect(),
            )
        }
        leaf => Ordered::Leaf(leaf.clone()),
    }
}

/// `merged` written as pretty JSON with a closing newline, its keys in the
/// order of the file it was read from (`before`, its bytes). With no file,
/// or one that is not JSON, the keys are sorted, as `serde_json` writes them.
pub fn pretty_in_order(before: Option<&[u8]>, merged: &Value) -> Result<String, String> {
    let before = before.and_then(|bytes| serde_json::from_slice::<Ordered>(bytes).ok());
    let ordered = in_order_of(before.as_ref(), merged);
    let mut body = serde_json::to_string_pretty(&ordered).map_err(|error| error.to_string())?;
    body.push('\n');
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_persons_order_is_kept_and_what_was_added_goes_last() {
        let before = br#"{"zeta": 1, "hooks": {"stop": [{"command": "a", "b": 2}], "after": []}, "alpha": [true, {"y": 1, "x": 2}]}"#;
        let mut merged: Value = serde_json::from_slice(before).unwrap();
        merged["hooks"]["beforeReadFile"] = json!([{"command": "guard"}]);
        merged["new"] = json!(null);
        merged.as_object_mut().unwrap().remove("alpha");
        let text = pretty_in_order(Some(before), &merged).unwrap();
        let at = |key: &str| text.find(&format!("\"{key}\"")).unwrap();
        assert!(
            at("zeta") < at("hooks") && at("hooks") < at("new"),
            "{text}"
        );
        assert!(
            at("stop") < at("after") && at("after") < at("beforeReadFile"),
            "{text}"
        );
        assert!(at("command") < at("b"), "{text}");
        assert!(!text.contains("alpha"), "{text}");
        assert!(text.ends_with("}\n"));
        let back: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back, merged, "the values are merged's");
    }

    #[test]
    fn nested_order_and_numbers_survive() {
        let before = br#"{"b": {"y": 1.5, "x": -3}, "a": [{"q": 1, "p": 2}]}"#;
        let merged: Value = serde_json::from_slice(before).unwrap();
        let text = pretty_in_order(Some(before), &merged).unwrap();
        assert!(
            text.find("\"y\"").unwrap() < text.find("\"x\"").unwrap(),
            "{text}"
        );
        assert!(
            text.find("\"q\"").unwrap() < text.find("\"p\"").unwrap(),
            "{text}"
        );
        assert!(
            text.find("\"b\"").unwrap() < text.find("\"a\"").unwrap(),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), merged);
    }

    #[test]
    fn no_file_or_a_broken_one_is_written_sorted() {
        let merged = json!({"b": 1, "a": 2});
        let sorted = format!("{}\n", serde_json::to_string_pretty(&merged).unwrap());
        assert_eq!(pretty_in_order(None, &merged).unwrap(), sorted);
        assert_eq!(pretty_in_order(Some(b"{ broken"), &merged).unwrap(), sorted);
    }
}
