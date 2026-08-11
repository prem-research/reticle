use std::borrow::Cow;

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

pub trait AssignedPolicy {
    /// specifies which package and rule dictates whether
    /// this set of claims is valid or not
    ///
    /// NOTE: must return a bool value or else an error will be thrown
    ///
    /// Example return value: `nvidia.allow`
    /// Which internally will try to query: `data.nvidia.allow`
    fn policy(&self) -> Cow<'static, str>;
}

impl<A: AssignedPolicy> AssignedPolicy for &A {
    fn policy(&self) -> Cow<'static, str> {
        (*self).policy()
    }
}

pub struct WithPolicy<'a, C: Verifiable + 'a> {
    claims: C::Claims<'a>,
    policy: Cow<'static, str>,
}

impl<'a, C: Verifiable + 'a> WithPolicy<'a, C> {
    pub fn new(policy: impl Into<Cow<'static, str>>, claims: C::Claims<'a>) -> Self {
        Self {
            claims,
            policy: policy.into(),
        }
    }
}

impl<C: Verifiable> AssignedPolicy for WithPolicy<'_, C> {
    fn policy(&self) -> Cow<'static, str> {
        self.policy.clone()
    }
}

#[derive(Default)]
pub struct ValidationBuilder {
    policy: Vec<String>,
    data: Vec<regorus::Value>,
}

impl ValidationBuilder {
    /// adds json data to the rego engine
    pub fn add_data_json(mut self, data: &str) -> Result<Self, AttestationError> {
        let reg_data = regorus::Value::from_json_str(data)
            .map_err(AttestationError::from_anyhow)
            .context("failed parsing rego data")?;

        self.data.push(reg_data);
        Ok(self)
    }

    /// adds multiple json objects to data at a single time
    pub fn add_datas_json(
        self,
        data: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<ValidationBuilder, AttestationError> {
        data.into_iter()
            .try_fold(self, |builder, data| builder.add_data_json(data.as_ref()))
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
    pub fn verify_claim<C: Verifiable>(
        &self,
        claims: WithPolicy<'_, C>,
    ) -> Result<ValidationResult, AttestationError> {
        // avois polluting the engine for further verifications
        // and allows us to have this method &self
        let mut engine = self.engine.clone();

        // convert claims to rego compatible format
        let value = serde_value::to_value(&claims.claims)?; //TODO
        let value = regorus::Value::deserialize(value)?;
        // here we set what input. will be in rego
        engine.set_input(value);

        let query = format!("data.{}", claims.policy());

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
