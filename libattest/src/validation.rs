use regorus::{Engine, Value};
use serde::{Deserialize, Serialize};

use crate::error::{AttestationError, Context};

/// Specifies the trait for an entity which produces
/// claims once cryptographically verified.
///
/// Associated type [`Self::Claims`] might borrow from self hence
/// the GAT containing the self-bound lifetime
pub trait Verifiable {
    type Claims<'a>: Serialize
    where
        Self: 'a;

    // Converts this set of claims into a rego engine compatible format
    // fn claims<'a>(&'a self) -> Self::Claims<'a>;
}

#[derive(Default)]
pub struct ValidationBuilder {
    policy: Vec<String>,
    data: Vec<regorus::Value>,
}

impl ValidationBuilder {
    /// Add caller-pinned policy data without changing its document namespace.
    /// This preserves policies using `data.reference_values`, alongside the
    /// measurements API used by the PodVM protocol.
    pub fn add_data_json(mut self, data: &str) -> crate::Result<Self> {
        let value = Value::from_json_str(data)
            .map_err(AttestationError::from_anyhow)
            .context("invalid policy data JSON")?;
        self.data.push(value);
        Ok(self)
    }

    pub fn add_meaurements(mut self, measurements: impl Serialize) -> crate::Result<Self> {
        #[derive(Serialize)]
        struct Measurements<T> {
            measurements: T,
        }

        let measurements = serde_value::to_value(&Measurements { measurements })?;
        let measurements = regorus::Value::deserialize(measurements)?;

        self.data.push(measurements);
        Ok(self)
    }

    /// add a rego policy
    pub fn add_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy.push(policy.into());
        self
    }

    pub fn add_policies(mut self, policy: impl IntoIterator<Item = String>) -> Self {
        self.policy.extend(policy);
        self
    }

    pub fn build(self) -> Result<Validator, AttestationError> {
        let mut engine = Engine::default();

        for policy in self.policy {
            engine
                .add_policy(String::new(), policy)
                .map_err(AttestationError::from_anyhow)
                .context("failed adding attestation policy to engine")?;
        }

        for data in self.data {
            engine
                .add_data(data)
                .map_err(AttestationError::from_anyhow)
                .context("failed adding data to engine")?;
        }

        let validation = Validator { engine };
        Ok(validation)
    }
}

#[derive(Debug)]
pub struct Validator {
    engine: Engine,
}

impl Validator {
    pub fn builder() -> ValidationBuilder {
        ValidationBuilder::default()
    }

    /// gets the rego query and input from `impl Claim` and then
    /// drives the engine to verify the query
    pub fn evaluate<S: Serialize>(
        &self,
        policy: &str,
        input: &S,
    ) -> Result<ValidationResult, AttestationError> {
        // avois polluting the engine for further verifications
        // and allows us to have this method &self
        let mut engine = self.engine.clone();

        // convert claims to rego compatible format
        let value = serde_value::to_value(input)?;
        let value = regorus::Value::deserialize(value)?;
        // here we set what input. will be in rego
        engine.set_input(value);

        let query = format!("data.{}", policy);

        engine.set_enable_coverage(true);
        let result = engine
            .eval_rule(query)
            .map_err(AttestationError::from_anyhow)
            .context("error running rego query")?;

        // we are expecting a bool value from our query
        let result = match result {
            Value::Bool(result) => result,
            _ => return AttestationError::internal("rego policy returned a non boolean result"),
        };

        let res = if result {
            ValidationResult::Success
        } else {
            let coverage = engine
                .get_coverage_report()
                .and_then(|report| report.to_string_pretty())
                .map_err(AttestationError::from_anyhow)?;

            ValidationResult::Failure { coverage }
        };

        Ok(res)
    }
}

#[derive(Clone, Debug)]
#[must_use]
pub enum ValidationResult {
    Success,
    Failure { coverage: String },
}

impl ValidationResult {
    pub fn or_err(self, msg: &'static str) -> Result<(), AttestationError> {
        match self {
            Self::Success => Ok(()),
            Self::Failure { coverage } => Err(AttestationError::new(coverage)).context(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_reference_data_keeps_its_namespace_and_denies_mismatches() {
        let validator = Validator::builder()
            .add_policy("package tdx\ndefault allow := false\nallow if { input == data.reference_values.expected }")
            .add_data_json(r#"{"reference_values":{"expected":"approved-node"}}"#)
            .unwrap().build().unwrap();
        assert!(
            validator
                .evaluate("tdx.allow", &"approved-node")
                .unwrap()
                .or_err("denied")
                .is_ok()
        );
        assert!(
            validator
                .evaluate("tdx.allow", &"other-node")
                .unwrap()
                .or_err("denied")
                .is_err()
        );
        assert!(validator.evaluate("tdx.missing", &"approved-node").is_err());
    }

    #[test]
    fn malformed_reference_data_is_rejected() {
        assert!(Validator::builder().add_data_json("{").is_err());
    }
}
