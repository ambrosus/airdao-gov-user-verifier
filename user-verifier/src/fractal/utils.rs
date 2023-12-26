use serde::{
    de::{self, Error},
    Deserialize,
};
use serde_json::Value;
use std::str::FromStr;
use uuid::Uuid;

pub fn de_array_separated_by_plus_sign<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    String::deserialize(deserializer)?
        .split('+')
        .filter_map(|sub| {
            if sub.is_empty() {
                None
            } else {
                Some(T::deserialize(Value::from(sub)).map_err(D::Error::custom))
            }
        })
        .collect::<Result<Vec<_>, D::Error>>()
}

pub fn de_from_uuid<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: From<Uuid>,
{
    let uuid = Uuid::from_str(&String::deserialize(deserializer)?)
        .map_err(|e| de::Error::custom(format!("Unable to deserialize uuid. Error: {e:?}")))?;

    Ok(T::from(uuid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{de::IntoDeserializer, Deserialize};

    #[test]
    fn test_de_array_separated_by_plus_sign() {
        #[derive(Deserialize, Debug, PartialEq)]
        #[serde(rename_all = "snake_case")]
        enum TestSubString {
            VarA,
            VarB,
            VarC,
        }

        struct TestCase<'a, T> {
            input: &'a str,
            expected: Result<Vec<T>, String>,
        }

        let test_cases = [
            TestCase {
                input: "var_a",
                expected: Ok(vec![TestSubString::VarA]),
            },
            TestCase {
                input: "var_a+var_b+var_c",
                expected: Ok(vec![
                    TestSubString::VarA,
                    TestSubString::VarB,
                    TestSubString::VarC,
                ]),
            },
            TestCase {
                input: "",
                expected: Ok(vec![]),
            },
            TestCase {
                input: "var_d",
                expected: Err(
                    "unknown variant `var_d`, expected one of `var_a`, `var_b`, `var_c`".to_owned(),
                ),
            },
        ];

        for (i, test_case) in test_cases.into_iter().enumerate() {
            assert_eq!(
                de_array_separated_by_plus_sign::<_, TestSubString>(
                    test_case.input.into_deserializer()
                )
                .map_err(|e: serde_json::Error| e.to_string()),
                test_case.expected,
                "Test case #{i}"
            );
        }
    }
}
