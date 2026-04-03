use std::{fmt::Debug, marker::PhantomData};

pub trait Policy<Claims> {
    type Error: Debug;

    fn appraise(&self, claims: &Claims) -> Result<(), Self::Error>;
}

pub struct Appraisal<Claims, E> {
    _a: PhantomData<(Claims, E)>,
    rules: Vec<Box<dyn Policy<Claims, Error = E>>>,
}

impl<Claims, E> Appraisal<Claims, E> {
    pub fn add_policy(&mut self, policy: impl Policy<Claims, Error = E> + 'static) {
        self.rules.push(Box::new(policy));

        todo!()
    }

    pub fn add_dyn_policy(&mut self, policy: Box<dyn Policy<Claims, Error = E>>) {
        self.rules.push(policy);
    }
}
