//! Original-text JSON validation shared by native HTTP and WASM adapters.
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use std::{collections::BTreeSet, fmt};

pub(crate) fn check_raw(json: &str) -> Result<(), &'static str> {
    check_raw_bytes(json.as_bytes())
}

pub(crate) fn check_raw_bytes(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() > crate::CONTROL_MESSAGE_BYTES as usize {
        return Err("RESOURCE_EXHAUSTED");
    }
    let json = std::str::from_utf8(bytes).map_err(|_| "INVALID_ARGUMENT")?;
    let mut decoder = serde_json::Deserializer::from_str(json);
    UniqueJson::deserialize(&mut decoder).map_err(|_| "INVALID_ARGUMENT")?;
    decoder.end().map_err(|_| "INVALID_ARGUMENT")
}
struct UniqueJson;
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_unit<E: de::Error>(self) -> Result<UniqueJson, E> {
                Ok(UniqueJson)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueJson, A::Error> {
                while seq.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UniqueJson, A::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    map.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
        }
        decoder.deserialize_any(UniqueVisitor)
    }
}
