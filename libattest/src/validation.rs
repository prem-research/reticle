use std::borrow::Cow;

use regorus::{Engine, Value};
use serde::{Deserialize, Serialize};

use crate::error::{AttestationError, Context};

pub trait Claim: AssignedPolicy {
    /// Converts this set of claims into a rego engine compatible format
    fn rego_repr(&self) -> impl Serialize;
}

pub trait IntoClaims {
    type Claims: Claim;
    fn into_claims(self) -> Self::Claims;
}

impl<C: Claim> IntoClaims for C {
    type Claims = C;
    fn into_claims(self) -> C {
        self
    }
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

pub struct WithPolicy<T: Serialize> {
    claims: T,
    policy: Cow<'static, str>,
}

impl<T: Serialize> WithPolicy<T> {
    pub fn new(policy: impl Into<Cow<'static, str>>, claims: T) -> Self {
        Self {
            claims,
            policy: policy.into(),
        }
    }
}

impl<T: Serialize> Claim for WithPolicy<T> {
    fn rego_repr(&self) -> impl Serialize {
        &self.claims
    }
}

impl<T: Serialize> AssignedPolicy for WithPolicy<T> {
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
    pub fn verify_claim(
        &self,
        claims: impl IntoClaims,
    ) -> Result<ValidationResult, AttestationError> {
        let claims = claims.into_claims();
        // avois polluting the engine for further verifications
        // and allows us to have this method &self
        let mut engine = self.engine.clone();

        // convert claims to rego compatible format
        let value = serde_value::to_value(claims.rego_repr())?;
        let value = regorus::Value::deserialize(value)?;
        // here we set what input. will be in rego
        engine.set_input(value);

        let query = format!("data.{}", claims.policy());
        let result = engine
            .eval_rule(query)
            .map_err(AttestationError::from_anyhow)
            .context("error running rego query")?;

        // we are expecting a bool value from our query
        let result = match result {
            Value::Bool(result) => result,
            _ => return AttestationError::internal("rego policy returned a non boolean result"),
        };

        Ok(ValidationResult(result))
    }
}

#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct ValidationResult(pub bool);

impl ValidationResult {
    pub fn or_err(self, msg: &'static str) -> Result<(), AttestationError> {
        self.0.then_some(()).context(msg)
    }
}

// pub struct Appraisal {
//     regorous: Engine,
// }

// impl Appraisal {
//     pub fn new() -> Self {
//         Appraisal {
//             regorous: Engine::default(),
//         }
//     }

//     pub fn set_policy(&self, policy: &str) {
//         self.regorous.add_polic
//     }

//     pub fn set_claims(claims: impl Claims) {}
// }
